"""One worker. The next row starts only after this one is submitted, failed, or skipped."""

from __future__ import annotations

import asyncio
import logging
import time

from app.browser_form import CONFIRMATION_CODE, submit_form
from app.settings import Settings
from app.submitter import BrowserUnavailable, SkipRequested, SubmissionError, TransientError, WorkerStopping

logger = logging.getLogger(__name__)

_BROWSER_BACKOFF_SECONDS = 15.0


async def run_worker(stop: asyncio.Event, store, settings: Settings, strategy, halt=None) -> None:
    await asyncio.to_thread(store.reset_interrupted)
    if not settings.form_url:
        logger.error("FORM_URL is not set; the report worker will not open a browser.")
    logger.info(
        "report worker started strategy=%s recaptcha=%s",
        settings.captcha_strategy,
        settings.recaptcha_version,
    )
    while not stop.is_set():
        paused = False
        try:
            worked = await asyncio.to_thread(
                process_available_once, store, settings, strategy, None, halt
            )
        except BrowserUnavailable:
            logger.warning("headed browser is unavailable; pending rows stay pending")
            worked = False
            paused = True
        except Exception:
            logger.exception("report worker failed")
            worked = False
        if worked:
            continue
        timeout = _BROWSER_BACKOFF_SECONDS if paused else settings.worker_interval
        try:
            await asyncio.wait_for(stop.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            continue


def process_available_once(store, settings: Settings, strategy, submit=None, halt=None) -> bool:
    """Take the next pending row and finish it before returning."""
    if submit is None and not settings.form_url:
        return False
    if halt is not None and halt.is_set():
        return False
    row = store.claim_next()
    if row is None:
        return False
    drive_target(store, settings, strategy, row, submit=submit, halt=halt)
    return True


def drive_target(store, settings: Settings, strategy, row: dict, submit=None, halt=None) -> None:
    def stopped() -> bool:
        return halt is not None and halt.is_set()

    while True:
        if stopped():
            store._release(row["target_id"])
            return
        if store.is_skip_requested(row["target_id"]):
            store.mark_skipped(row["target_id"])
            return
        try:
            if submit is None:
                code = _submit(store, settings, strategy, row, halt)
            else:
                code = submit(
                    row,
                    lambda: store._set_status(row["target_id"], "awaiting_captcha", None, None),
                    lambda: store.is_skip_requested(row["target_id"]),
                )
        except SkipRequested:
            store.mark_skipped(row["target_id"])
            return
        except WorkerStopping:
            store._release(row["target_id"])
            return
        except TransientError as exc:
            message = str(exc).strip()[:500] or "The form could not be submitted."
            outcome = store.note_transient(row["target_id"], message, settings.max_attempts)
            if outcome != "retry":
                return
            if not _wait_backoff(
                store, row["target_id"], int(row["attempts"]), settings.retry_base_seconds, halt
            ):
                return
            resumed = store.resume_retry(row["target_id"])
            if resumed is None:
                return
            row = resumed
            continue
        except SubmissionError as exc:
            message = str(exc).strip()[:500] or "The form could not be submitted."
            store._set_status(row["target_id"], "failed", message, None)
            return
        except BrowserUnavailable:
            store._release(row["target_id"])
            raise
        except Exception:
            logger.exception("submission attempt failed for job %s", row["job_id"])
            store._set_status(row["target_id"], "failed", "The form could not be submitted.", None)
            return
        else:
            if isinstance(code, str) and CONFIRMATION_CODE.fullmatch(code):
                store._set_status(row["target_id"], "submitted", None, code)
                store._record_log(row)
            else:
                store._set_status(
                    row["target_id"],
                    "failed",
                    "The confirmation page did not include a CF code.",
                    None,
                )
            return


def backoff_seconds(attempt: int, base: float) -> float:
    """5s, 15s, 45s when base is 5 and attempt is 1, 2, 3."""
    if attempt < 1:
        attempt = 1
    return base * (3 ** (attempt - 1))


def _wait_backoff(store, target_id: int, attempt: int, base: float, halt=None) -> bool:
    """Sleep until the next try. Return False when the row was skipped instead."""
    delay = backoff_seconds(attempt, base)
    deadline = time.monotonic() + max(delay, 0)
    while True:
        if halt is not None and halt.is_set():
            store._release(target_id)
            return False
        if store.is_skip_requested(target_id):
            store.mark_skipped(target_id)
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        time.sleep(min(0.2, remaining))


def _submit(store, settings: Settings, strategy, row: dict, halt=None) -> str:
    def on_captcha() -> None:
        logger.info(
            "captcha %s %s for %s",
            settings.captcha_strategy,
            settings.recaptcha_version,
            row.get("normalized"),
        )
        store._set_status(row["target_id"], "awaiting_captcha", None, None)

    def skip_check() -> bool:
        return store.is_skip_requested(row["target_id"])

    def stop_check() -> bool:
        return halt is not None and halt.is_set()

    return submit_form(
        settings.form_url,
        row,
        headless=settings.browser_headless,
        no_sandbox=settings.browser_no_sandbox,
        captcha_timeout_ms=int(settings.captcha_timeout_seconds * 1000),
        on_captcha=on_captcha,
        strategy=strategy,
        skip_check=skip_check,
        stop_check=stop_check,
    )
