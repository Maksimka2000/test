"""Errors the form worker can raise. Messages on SubmissionError are shown on the job."""

from __future__ import annotations


class SubmissionError(Exception):
    """A failure that will not change if the same row is tried again."""


class TransientError(SubmissionError):
    """A failure worth another attempt: timeouts, upload errors, a page that did not load."""


class SkipRequested(Exception):
    """The operator asked to leave this row and move on."""


class WorkerStopping(Exception):
    """The process is shutting down. The current row goes back to pending."""


class BrowserUnavailable(Exception):
    """Chromium did not start. The current row goes back to pending."""
