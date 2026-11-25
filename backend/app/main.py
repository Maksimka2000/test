"""HTTP API. Behavior and limits follow openapi.yaml."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from app.contract import Contract, load_contract
from app.errors import field_error
from app.settings import Settings
from app.store import Store
from app.strategies import load_strategy
from app.validation import validate_submission
from app.status import AWAITING_CAPTCHA, FAILED, PENDING, RETRYING, RUNNING, SKIPPED, SUBMITTED
from app.worker import backoff_seconds, run_worker

logger = logging.getLogger(__name__)

_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def create_app() -> FastAPI:
    logging.basicConfig(level=_log_level())
    contract = load_contract()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings = Settings.from_env()
        strategy = load_strategy(settings.captcha_strategy, settings)
        store = Store(settings.data_dir, max_attempts=settings.max_attempts)
        app.state.settings = settings
        app.state.store = store
        app.state.strategy = strategy
        stop = asyncio.Event()
        halt = threading.Event()
        task = None
        if settings.run_worker:
            task = asyncio.create_task(run_worker(stop, store, settings, strategy, halt))
        try:
            yield
        finally:
            halt.set()
            stop.set()
            if task is not None:
                try:
                    await asyncio.wait_for(task, timeout=20)
                except asyncio.TimeoutError:
                    logger.exception("worker did not stop within 20 seconds")
                    task.cancel()
                except Exception:
                    logger.exception("worker stopped with an error")
            store.close()

    app = FastAPI(
        title=contract.spec["info"]["title"],
        version=str(contract.spec["info"]["version"]),
        lifespan=lifespan,
        redirect_slashes=False,
    )
    app.state.contract = contract
    app.openapi_schema = contract.spec

    def openapi() -> dict:
        app.openapi_schema = contract.spec
        return app.openapi_schema

    app.openapi = openapi
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    _register_routes(app)
    return app


def _queue_document(request: Request) -> dict:
    settings = request.app.state.settings
    rows = request.app.state.store.list_queue()
    counts = {status: 0 for status in (PENDING, RUNNING, AWAITING_CAPTCHA, RETRYING, SUBMITTED, FAILED, SKIPPED)}
    seen_jobs = set()
    duplicates = 0
    targets = []
    for row in rows:
        status = row["status"]
        counts[status] = counts.get(status, 0) + 1
        if row["job_id"] not in seen_jobs:
            seen_jobs.add(row["job_id"])
            duplicates += int(row["duplicates_removed"])
        targets.append(
            {
                "id": row["id"],
                "job_id": row["job_id"],
                "position": row["position"],
                "input": row["original"],
                "value": row["normalized"],
                "status": status,
                "attempts": row["attempts"],
                "error": row["error"],
                "confirmation_code": row["confirmation_code"],
                "paused": bool(row["paused"]),
                "queued_at": row["queued_at"],
                "timeout_seconds": _timeout_seconds(row, settings),
            }
        )
    return {
        "max_attempts": settings.max_attempts,
        "captcha_timeout_seconds": int(settings.captcha_timeout_seconds),
        "summary": {
            "total": len(targets),
            "duplicates_removed": duplicates,
            **counts,
        },
        "targets": targets,
    }


def _timeout_seconds(row: dict, settings) -> int | None:
    status = row["status"]
    if status == AWAITING_CAPTCHA:
        budget = settings.captcha_timeout_seconds
    elif status == RETRYING:
        budget = backoff_seconds(int(row["attempts"]), settings.retry_base_seconds)
    else:
        return None
    started = datetime.strptime(row["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    remaining = budget - (datetime.now(timezone.utc) - started).total_seconds()
    return max(0, int(remaining))


def _log_level() -> int:
    name = os.environ.get("LOG_LEVEL", "INFO").upper()
    return getattr(logging, name, logging.INFO)


def _register_routes(app: FastAPI) -> None:
    @app.get("/health")
    def health(request: Request) -> dict:
        current: Contract = request.app.state.contract
        return {
            "status": "ok",
            "limits": {
                "maxBatchSize": current.max_batch_size,
                "maxEvidenceBytes": current.max_evidence_bytes,
                "maxReasonLength": current.max_reason_length,
                "maxTargetsChars": current.max_targets_chars,
                "maxUrlLength": current.max_url_length,
                "allowedEvidenceTypes": list(current.evidence_types),
            },
            "enums": {
                "submissionType": list(current.submission_types),
                "threatType": list(current.threat_types),
            },
            "captcha_strategy": request.app.state.settings.captcha_strategy,
        }

    @app.post("/jobs", status_code=201)
    async def create_job(request: Request, response: Response):
        current: Contract = request.app.state.contract
        if "multipart/form-data" not in request.headers.get("content-type", "").lower():
            raise HTTPException(status_code=415, detail="Content-Type must be multipart/form-data.")
        form = await _read_form(request, current)
        try:
            document = await _create_from_form(request, form)
        finally:
            await form.close()
        response.headers["Location"] = f"/jobs/{document['id']}"
        return document

    @app.get("/queue")
    def get_queue(request: Request):
        return _queue_document(request)

    @app.post("/queue/retry-failed")
    def retry_failed_queue(request: Request):
        store: Store = request.app.state.store
        if store.requeue_all_failed() == 0:
            raise HTTPException(status_code=409, detail="No failed targets to re-queue.")
        return _queue_document(request)

    @app.get("/jobs/{job_id}")
    def get_job(job_id: str, request: Request):
        job = request.app.state.store.get_job(_parse_job_id(job_id))
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found.")
        return job

    @app.post("/jobs/{job_id}/retry")
    def retry_job(job_id: str, request: Request):
        store: Store = request.app.state.store
        parsed_id = _parse_job_id(job_id)
        result = store.requeue_failed(parsed_id)
        if result == "missing":
            raise HTTPException(status_code=404, detail="Job not found.")
        if result == "empty":
            raise HTTPException(status_code=409, detail="No failed targets to re-queue.")
        return store.get_job(parsed_id)

    @app.post("/jobs/{job_id}/retry-failed")
    def retry_failed(job_id: str, request: Request):
        return retry_job(job_id, request)

    @app.post("/jobs/{job_id}/pause")
    def pause_job(job_id: str, request: Request):
        return _set_paused(job_id, request, True)

    @app.post("/jobs/{job_id}/resume")
    def resume_job(job_id: str, request: Request):
        return _set_paused(job_id, request, False)

    @app.post("/targets/{target_id}/skip")
    def skip_target(target_id: str, request: Request):
        store: Store = request.app.state.store
        parsed = _parse_target_id(target_id)
        result = store.request_skip(parsed)
        if result == "missing":
            raise HTTPException(status_code=404, detail="Target not found.")
        if result == "rejected":
            raise HTTPException(status_code=409, detail="This target cannot be skipped.")
        return store.get_job(store.job_id_for_target(parsed))

    @app.post("/targets/{target_id}/retry")
    def retry_target(target_id: str, request: Request):
        store: Store = request.app.state.store
        parsed = _parse_target_id(target_id)
        result = store.requeue_target(parsed)
        if result == "missing":
            raise HTTPException(status_code=404, detail="Target not found.")
        if result == "rejected":
            raise HTTPException(status_code=409, detail="This target cannot be retried.")
        return store.get_job(store.job_id_for_target(parsed))


class _ContractParser(MultiPartParser):
    """Let the contract validators see a slightly oversized part, then reject it.

    Starlette's parser otherwise stops text parts at 1 MiB before our character
    limit can run, and does not apply the evidence byte cap to files.
    """

    def __init__(self, headers, stream, *, text_limit: int, file_limit: int) -> None:
        super().__init__(headers, stream)
        self.max_part_size = text_limit
        self._file_limit = file_limit
        self._file_seen = 0

    def on_part_begin(self) -> None:
        self._file_seen = 0
        super().on_part_begin()

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        if self._current_part.file is not None:
            self._file_seen += end - start
            if self._file_seen > self._file_limit:
                raise MultiPartException("evidence too large")
        super().on_part_data(data, start, end)


async def _read_form(request: Request, contract: Contract):
    text_limit = max(contract.max_targets_chars, contract.max_reason_length) * 4 + 4096
    file_limit = contract.max_evidence_bytes + 64 * 1024
    parser = _ContractParser(
        request.headers,
        request.stream(),
        text_limit=text_limit,
        file_limit=file_limit,
    )
    try:
        return await parser.parse()
    except MultiPartException as exc:
        if exc.message == "evidence too large":
            message = f"Evidence file exceeds {contract.max_evidence_bytes} bytes."
            location = ("body", "evidence")
            error_type = "value_error.file_size"
        elif "maximum size" in exc.message.lower():
            message = "A form part exceeds the upload limit."
            location = ("body",)
            error_type = "value_error.upload_size"
        else:
            message = "The multipart body could not be read."
            location = ("body",)
            error_type = "value_error.multipart"
        raise HTTPException(
            status_code=422,
            detail=[field_error(location, message, error_type)],
        ) from exc


def _set_paused(job_id: str, request: Request, paused: bool):
    store: Store = request.app.state.store
    parsed_id = _parse_job_id(job_id)
    if store.set_paused(parsed_id, paused) == "missing":
        raise HTTPException(status_code=404, detail="Job not found.")
    return store.get_job(parsed_id)


def _parse_target_id(target_id: str) -> int:
    if not target_id.isdigit() or int(target_id) < 1:
        raise HTTPException(
            status_code=422,
            detail=[
                field_error(
                    ("path", "id"),
                    "Target id must be a positive integer.",
                    "value_error.integer",
                )
            ],
        )
    return int(target_id)


def _parse_job_id(job_id: str) -> str:
    if not _UUID.fullmatch(job_id):
        raise HTTPException(
            status_code=422,
            detail=[field_error(("path", "id"), "Job id must be a UUID.", "value_error.uuid")],
        )
    return job_id.lower()


async def _create_from_form(request: Request, form) -> dict:
    contract: Contract = request.app.state.contract
    evidence = form.get("evidence")
    filename = None
    declared_type = None
    content = None
    evidence_error = None
    if not isinstance(evidence, UploadFile):
        evidence_error = field_error(("body", "evidence"), "Evidence file is required.", "missing")
    else:
        filename = evidence.filename
        declared_type = evidence.content_type
        content, evidence_error = await _read_capped(evidence, contract.max_evidence_bytes)

    parsed, errors = validate_submission(
        contract,
        submission_type=_text(form, "submission_type"),
        targets=_text(form, "targets"),
        threat_type=_text(form, "threat_type"),
        reason=_text(form, "reason"),
        filename=filename,
        declared_type=declared_type,
        evidence=content,
        evidence_error=evidence_error,
    )
    if parsed is None:
        raise HTTPException(
            status_code=422,
            detail=errors
            or [field_error(("body",), "The submission is invalid.", "value_error")],
        )
    return request.app.state.store.create_job(parsed)


def _text(form, name: str) -> str | None:
    value = form.get(name)
    if isinstance(value, UploadFile) or not isinstance(value, str):
        return None
    return value


async def _read_capped(upload: UploadFile, max_bytes: int) -> tuple[bytes | None, dict | None]:
    chunks = []
    total = 0
    while True:
        block = await upload.read(64 * 1024)
        if not block:
            break
        total += len(block)
        if total > max_bytes:
            return None, field_error(
                ("body", "evidence"),
                f"Evidence file exceeds {max_bytes} bytes.",
                "value_error.file_size",
            )
        chunks.append(block)
    return b"".join(chunks), None


app = create_app()
