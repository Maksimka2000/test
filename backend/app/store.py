"""SQLite job store. One shared connection, serialized by a lock."""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.status import (
    AWAITING_CAPTCHA,
    FAILED,
    INTERRUPTED,
    PENDING,
    RETRYING,
    RUNNING,
    SKIPPED,
    STATUSES,
    SUBMITTED,
)
from app.submitter import BrowserUnavailable, SubmissionError
from app.validation import ParsedSubmission

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    submission_type TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_filename TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    evidence_mime TEXT NOT NULL,
    evidence_size INTEGER NOT NULL,
    duplicates_removed INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    position INTEGER NOT NULL,
    original TEXT NOT NULL,
    normalized TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    confirmation_code TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE (job_id, normalized),
    UNIQUE (job_id, position)
);

CREATE TABLE IF NOT EXISTS submission_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    target_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    submission_type TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_filename TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status, id);
"""

CONFIRMATION_CODE = re.compile(r"CF-[A-Z0-9]{8}")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def job_document(job: sqlite3.Row, targets: list, *, max_attempts: int) -> dict:
    counts = {status: 0 for status in STATUSES}
    presented = []
    for row in targets:
        counts[row["status"]] += 1
        presented.append(
            {
                "id": row["id"],
                "position": row["position"],
                "input": row["original"],
                "value": row["normalized"],
                "status": row["status"],
                "attempts": row["attempts"],
                "error": row["error"],
                "confirmation_code": row["confirmation_code"],
            }
        )
    return {
        "id": job["id"],
        "paused": bool(job["paused"]),
        "max_attempts": max_attempts,
        "submission_type": job["submission_type"],
        "threat_type": job["threat_type"],
        "reason": job["reason"],
        "evidence": {
            "filename": job["evidence_filename"],
            "media_type": job["evidence_mime"],
            "size_bytes": job["evidence_size"],
        },
        "created_at": job["created_at"],
        "summary": {
            "total": len(presented),
            "pending": counts[PENDING],
            "running": counts[RUNNING],
            "awaiting_captcha": counts[AWAITING_CAPTCHA],
            "retrying": counts[RETRYING],
            "submitted": counts[SUBMITTED],
            "failed": counts[FAILED],
            "skipped": counts[SKIPPED],
            "duplicates_removed": job["duplicates_removed"],
        },
        "targets": presented,
    }


class Store:
    def __init__(self, data_dir: Path, max_attempts: int = 3):
        self.max_attempts = max_attempts
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.data_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.data_dir / "reports.db",
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.executescript(_SCHEMA)
            self._ensure_columns()
            self._conn.execute("UPDATE targets SET status = ? WHERE status = ?", (PENDING, "queued"))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def create_job(self, parsed: ParsedSubmission) -> dict:
        job_id = str(uuid.uuid4())
        suffix = Path(parsed.evidence.filename).suffix.lower()
        disk_path = self.evidence_dir / f"{job_id}{suffix}"
        partial = disk_path.with_suffix(disk_path.suffix + ".part")
        partial.write_bytes(parsed.evidence.content)
        os.replace(partial, disk_path)
        created_at = utc_now()
        try:
            with self._lock:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    self._conn.execute(
                        """
                        INSERT INTO jobs (
                            id, submission_type, threat_type, reason,
                            evidence_filename, evidence_path, evidence_mime,
                            evidence_size, duplicates_removed, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            job_id,
                            parsed.submission_type,
                            parsed.threat_type,
                            parsed.reason,
                            parsed.evidence.filename,
                            str(disk_path),
                            parsed.evidence.media_type,
                            parsed.evidence.size_bytes,
                            parsed.duplicates_removed,
                            created_at,
                        ),
                    )
                    self._conn.executemany(
                        """
                        INSERT INTO targets (
                            job_id, position, original, normalized, status,
                            attempts, error, updated_at
                        ) VALUES (?, ?, ?, ?, ?, 0, NULL, ?)
                        """,
                        [
                            (
                                job_id,
                                position,
                                target.original,
                                target.normalized,
                                PENDING,
                                created_at,
                            )
                            for position, target in enumerate(parsed.targets, start=1)
                        ],
                    )
                    self._conn.commit()
                except Exception:
                    self._conn.rollback()
                    raise
        except Exception:
            disk_path.unlink(missing_ok=True)
            partial.unlink(missing_ok=True)
            raise
        document = self.get_job(job_id)
        if document is None:
            raise RuntimeError(f"Stored job {job_id} could not be read back.")
        logger.info(
            "created job %s targets=%s duplicates_removed=%s",
            job_id,
            document["summary"]["total"],
            document["summary"]["duplicates_removed"],
        )
        return document

    def get_job(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if job is None:
                return None
            targets = self._conn.execute(
                "SELECT * FROM targets WHERE job_id = ? ORDER BY position",
                (job_id,),
            ).fetchall()
            return job_document(job, targets, max_attempts=self.max_attempts)

    def requeue_failed(self, job_id: str) -> str:
        """Return missing, empty, or ok."""
        with self._lock:
            found = self._conn.execute("SELECT 1 FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if found is None:
                return "missing"
            cursor = self._conn.execute(
                """
                UPDATE targets
                SET status = ?, error = NULL, confirmation_code = NULL,
                    skip_requested = 0, updated_at = ?
                WHERE job_id = ? AND status = ?
                """,
                (PENDING, utc_now(), job_id, FAILED),
            )
            if cursor.rowcount == 0:
                return "empty"
            logger.info("re-queued %s failed target(s) on job %s", cursor.rowcount, job_id)
            return "ok"

    def list_queue(self) -> list:
        """Every target, newest batch first, original line order inside a batch."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    targets.id AS id,
                    targets.job_id AS job_id,
                    targets.position AS position,
                    targets.original AS original,
                    targets.normalized AS normalized,
                    targets.status AS status,
                    targets.attempts AS attempts,
                    targets.error AS error,
                    targets.confirmation_code AS confirmation_code,
                    targets.updated_at AS updated_at,
                    jobs.paused AS paused,
                    jobs.created_at AS queued_at,
                    jobs.duplicates_removed AS duplicates_removed
                FROM targets
                JOIN jobs ON jobs.id = targets.job_id
                ORDER BY jobs.rowid DESC, targets.position ASC, targets.id ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def requeue_all_failed(self) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE targets
                SET status = ?, error = NULL, confirmation_code = NULL,
                    skip_requested = 0, updated_at = ?
                WHERE status = ?
                """,
                (PENDING, utc_now(), FAILED),
            )
            return cursor.rowcount

    def count_jobs(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM jobs").fetchone()
            return int(row["n"])

    def count_submissions(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM submission_log").fetchone()
            return int(row["n"])

    def reset_interrupted(self) -> int:
        """Return rows abandoned by a restart to the tail of the FIFO queue."""
        placeholders = ", ".join("?" for _ in INTERRUPTED)
        with self._lock:
            cursor = self._conn.execute(
                f"""
                UPDATE targets
                SET status = ?, error = NULL, confirmation_code = NULL, updated_at = ?
                WHERE status IN ({placeholders})
                """,
                (PENDING, utc_now(), *INTERRUPTED),
            )
            if cursor.rowcount:
                logger.info("returned %s interrupted target(s) to pending", cursor.rowcount)
            return cursor.rowcount

    def claim_next(self) -> dict | None:
        """Mark the next pending row running. Newest batch first, then position."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._settle_pending_skips()
                row = self._conn.execute(
                    """
                    SELECT
                        targets.id AS target_id,
                        targets.position AS position,
                        targets.attempts AS attempts,
                        targets.original AS original,
                        targets.normalized AS normalized,
                        targets.job_id AS job_id,
                        jobs.submission_type AS submission_type,
                        jobs.threat_type AS threat_type,
                        jobs.reason AS reason,
                        jobs.evidence_filename AS evidence_filename,
                        jobs.evidence_path AS evidence_path
                    FROM targets
                    JOIN jobs ON jobs.id = targets.job_id
                    WHERE targets.status = ?
                      AND targets.skip_requested = 0
                      AND jobs.paused = 0
                    ORDER BY jobs.rowid DESC, targets.position, targets.id
                    LIMIT 1
                    """,
                    (PENDING,),
                ).fetchone()
                if row is None:
                    self._conn.commit()
                    return None
                cursor = self._conn.execute(
                    """
                    UPDATE targets
                    SET status = ?, attempts = attempts + 1, error = NULL, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (RUNNING, utc_now(), row["target_id"], PENDING),
                )
                if cursor.rowcount != 1:
                    self._conn.rollback()
                    return None
                self._conn.commit()
                claimed = dict(row)
                claimed["attempts"] = int(row["attempts"]) + 1
                return claimed
            except Exception:
                self._conn.rollback()
                raise

    def process_next(self, submit) -> bool:
        """Fill and submit one pending row. submit(row, on_captcha) returns a CF code."""
        row = self.claim_next()
        if row is None:
            return False

        def on_captcha() -> None:
            self._set_status(row["target_id"], AWAITING_CAPTCHA, None, None)

        try:
            code = submit(row, on_captcha)
        except BrowserUnavailable:
            self._release(row["target_id"])
            raise
        except SubmissionError as exc:
            message = str(exc).strip()[:500] or "The form could not be submitted."
            self._set_status(row["target_id"], FAILED, message, None)
        except Exception:
            logger.exception("submission attempt failed for job %s", row["job_id"])
            self._set_status(row["target_id"], FAILED, "The form could not be submitted.", None)
        else:
            if isinstance(code, str) and CONFIRMATION_CODE.fullmatch(code):
                self._set_status(row["target_id"], SUBMITTED, None, code)
                self._record_log(row)
            else:
                self._set_status(
                    row["target_id"],
                    FAILED,
                    "The confirmation page did not include a CF code.",
                    None,
                )
        return True

    def _release(self, target_id: int) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE targets
                SET status = ?, attempts = MAX(attempts - 1, 0),
                    error = NULL, confirmation_code = NULL, updated_at = ?
                WHERE id = ? AND status IN (?, ?)
                """,
                (PENDING, utc_now(), target_id, RUNNING, AWAITING_CAPTCHA),
            )

    def request_skip(self, target_id: int) -> str:
        """Return missing, rejected, skipped, or armed."""
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            if row is None:
                return "missing"
            status = row["status"]
            if status in (SUBMITTED, FAILED):
                return "rejected"
            if status == SKIPPED:
                return "skipped"
            if status == PENDING:
                self._conn.execute(
                    """
                    UPDATE targets
                    SET status = ?, skip_requested = 1, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (SKIPPED, utc_now(), target_id, PENDING),
                )
                return "skipped"
            self._conn.execute(
                "UPDATE targets SET skip_requested = 1, updated_at = ? WHERE id = ?",
                (utc_now(), target_id),
            )
            return "armed"

    def requeue_target(self, target_id: int) -> str:
        """Return missing, rejected, or ok. Failed and skipped rows go back to pending."""
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            if row is None:
                return "missing"
            if row["status"] not in (FAILED, SKIPPED):
                return "rejected"
            self._conn.execute(
                """
                UPDATE targets
                SET status = ?, error = NULL, confirmation_code = NULL,
                    skip_requested = 0, updated_at = ?
                WHERE id = ? AND status IN (?, ?)
                """,
                (PENDING, utc_now(), target_id, FAILED, SKIPPED),
            )
            return "ok"

    def set_paused(self, job_id: str, paused: bool) -> str:
        """Return missing or ok. The current row is allowed to finish."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE jobs SET paused = ? WHERE id = ?",
                (1 if paused else 0, job_id),
            )
            if cursor.rowcount != 1:
                return "missing"
            return "ok"

    def job_id_for_target(self, target_id: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT job_id FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            if row is None:
                return None
            return row["job_id"]

    def is_skip_requested(self, target_id: int) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT skip_requested FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            return bool(row and row["skip_requested"])

    def mark_skipped(self, target_id: int) -> None:
        self._set_status(target_id, SKIPPED, None, None)

    def note_transient(self, target_id: int, message: str, max_attempts: int) -> str:
        """Return retry or failed. The attempt counter already includes this try."""
        with self._lock:
            row = self._conn.execute(
                "SELECT attempts FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            if row is None or int(row["attempts"]) >= max_attempts:
                self._set_status(target_id, FAILED, message, None)
                return "failed"
        self._set_status(target_id, RETRYING, message, None)
        return "retry"

    def resume_retry(self, target_id: int) -> dict | None:
        """Start the next try of the same row, or skip it when the operator asked."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT status, skip_requested, attempts FROM targets WHERE id = ?",
                    (target_id,),
                ).fetchone()
                if row is None:
                    self._conn.commit()
                    return None
                if row["skip_requested"]:
                    self._conn.execute(
                        "UPDATE targets SET status = ?, updated_at = ? WHERE id = ?",
                        (SKIPPED, utc_now(), target_id),
                    )
                    self._conn.commit()
                    return None
                if row["status"] != RETRYING:
                    self._conn.commit()
                    return None
                self._conn.execute(
                    """
                    UPDATE targets
                    SET status = ?, attempts = attempts + 1, error = NULL, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (RUNNING, utc_now(), target_id, RETRYING),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self._load_work_row(target_id)

    def _settle_pending_skips(self) -> None:
        self._conn.execute(
            """
            UPDATE targets
            SET status = ?, updated_at = ?
            WHERE status = ? AND skip_requested = 1
            """,
            (SKIPPED, utc_now(), PENDING),
        )

    def _load_work_row(self, target_id: int) -> dict | None:
        with self._lock:
            return self._load_work_row_unlocked(target_id)

    def _load_work_row_unlocked(self, target_id: int) -> dict | None:
        row = self._conn.execute(
            """
            SELECT
                targets.id AS target_id,
                targets.position AS position,
                targets.attempts AS attempts,
                targets.original AS original,
                targets.normalized AS normalized,
                targets.job_id AS job_id,
                jobs.submission_type AS submission_type,
                jobs.threat_type AS threat_type,
                jobs.reason AS reason,
                jobs.evidence_filename AS evidence_filename,
                jobs.evidence_path AS evidence_path
            FROM targets
            JOIN jobs ON jobs.id = targets.job_id
            WHERE targets.id = ?
            """,
            (target_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def _ensure_columns(self) -> None:
        self._add_column("targets", "confirmation_code", "TEXT")
        self._add_column("targets", "skip_requested", "INTEGER NOT NULL DEFAULT 0")
        self._add_column("jobs", "paused", "INTEGER NOT NULL DEFAULT 0")

    def _add_column(self, table: str, name: str, declaration: str) -> None:
        columns = {row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")}
        if name not in columns:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def _set_status(self, target_id: int, status: str, error: str | None, code: str | None) -> None:
        if status not in STATUSES:
            raise ValueError(status)
        with self._lock:
            self._conn.execute(
                """
                UPDATE targets
                SET status = ?, error = ?, confirmation_code = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, error, code, utc_now(), target_id),
            )

    def _record_log(self, row: dict) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO submission_log (
                    job_id, target_id, value, submission_type, threat_type,
                    reason, evidence_filename, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["job_id"],
                    row["target_id"],
                    row["normalized"],
                    row["submission_type"],
                    row["threat_type"],
                    row["reason"],
                    row["evidence_filename"],
                    utc_now(),
                ),
            )
