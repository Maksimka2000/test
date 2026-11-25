"""Fill one report form, then hand the page to the captcha strategy.

The worker does not open the next target until this call returns.
"""

from __future__ import annotations

import logging
import re

from app.strategies import PAGE_STATE, ManualCaptchaStrategy
from app.submitter import BrowserUnavailable, SkipRequested, SubmissionError, TransientError, WorkerStopping

logger = logging.getLogger(__name__)

CONFIRMATION_CODE = re.compile(r"CF-[A-Z0-9]{8}")
THREAT_LABELS = {
    "phishing": "Phishing",
    "malware": "Malware",
    "spam": "Spam",
    "scam": "Fraud / Scam",
    "c2": "Botnet C&C",
    "other": "Other",
}
TARGET_FIELDS = {
    "domain": "#domain",
    "ip": "#ip",
    "url": "#url",
}


def extract_confirmation(page_text: str) -> str | None:
    match = CONFIRMATION_CODE.search(page_text or "")
    if match is None:
        return None
    return match.group(0)


def submit_form(
    form_url: str,
    row: dict,
    *,
    headless: bool,
    captcha_timeout_ms: int,
    on_captcha,
    strategy=None,
    skip_check=None,
    stop_check=None,
    no_sandbox: bool = False,
) -> str:
    """Open one form, run the captcha strategy, submit, and return the CF code."""
    if not form_url:
        raise SubmissionError("FORM_URL is not set.")
    field = TARGET_FIELDS.get(row["submission_type"])
    threat = THREAT_LABELS.get(row["threat_type"])
    if field is None or threat is None:
        raise SubmissionError("This row does not match the report form.")
    if strategy is None:
        strategy = ManualCaptchaStrategy()
    if skip_check is None:
        skip_check = lambda: False
    if stop_check is None:
        stop_check = lambda: False

    def checkpoint() -> None:
        if stop_check():
            raise WorkerStopping()
        if skip_check():
            raise SkipRequested()

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise BrowserUnavailable("Playwright is not installed.") from exc

    try:
        with sync_playwright() as playwright:
            try:
                launch_args = ["--no-sandbox", "--disable-dev-shm-usage"] if no_sandbox else []
                browser = playwright.chromium.launch(headless=headless, args=launch_args)
            except PlaywrightError as exc:
                raise BrowserUnavailable("The headed browser could not be opened.") from exc
            try:
                page = browser.new_page()
                checkpoint()
                _goto(page, form_url)
                checkpoint()
                _choose(page, "#submission_type", row["submission_type"], "submission type")
                _fill(page, field, row["normalized"], "target")
                _choose(page, "#threat_type", threat, "threat type")
                _fill(page, "#reason", row["reason"], "reason")
                _attach(page, row["evidence_path"])
                checkpoint()
                terms = page.locator("input[name='accept_terms']")
                if terms.count():
                    terms.check()
                on_captcha()
                strategy.handle(
                    page,
                    row,
                    timeout_ms=captcha_timeout_ms,
                    skip_check=skip_check,
                    stop_check=stop_check,
                )
                checkpoint()
                if page.evaluate(PAGE_STATE) != "done":
                    try:
                        page.click("button[type=submit]")
                        page.wait_for_load_state("domcontentloaded", timeout=45000)
                    except PlaywrightError:
                        logger.info("submit click overlapped a navigation for job %s", row["job_id"])
                code = extract_confirmation(page.inner_text("body"))
                if code is None:
                    raise SubmissionError(_failure_reason(page))
                return code
            finally:
                browser.close()
    except (BrowserUnavailable, SubmissionError, SkipRequested, WorkerStopping):
        raise
    except PlaywrightError as exc:
        logger.info("browser closed during submission for job %s", row["job_id"])
        raise _mapped_browser_error(exc) from exc


def _goto(page, form_url: str) -> None:
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.goto(form_url, wait_until="domcontentloaded", timeout=45000)
    except PlaywrightError as exc:
        if "timeout" in str(exc).lower():
            raise TransientError("The report form did not finish loading.") from exc
        raise TransientError("The report form did not finish loading.") from exc


def _choose(page, selector: str, value: str, label: str) -> None:
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.select_option(selector, value, timeout=8000)
    except PlaywrightError as exc:
        raise SubmissionError(f"The form no longer has the {label} field.") from exc


def _fill(page, selector: str, value: str, label: str) -> None:
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.fill(selector, value, timeout=8000)
    except PlaywrightError as exc:
        raise SubmissionError(f"The form no longer has the {label} field.") from exc


def _attach(page, evidence_path: str) -> None:
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.set_input_files("#attachment", evidence_path, timeout=15000)
    except PlaywrightError as exc:
        raise TransientError("The evidence file could not be attached.") from exc


def _failure_reason(page) -> str:
    parts = []
    for selector in (".alert", ".field-error"):
        locator = page.locator(selector)
        count = min(locator.count(), 3)
        for index in range(count):
            text = locator.nth(index).inner_text().strip()
            if text:
                parts.append(text)
    if parts:
        return " ".join(parts)[:500]
    return "The confirmation page did not include a CF code."


def _mapped_browser_error(exc: Exception) -> Exception:
    text = str(exc).lower()
    if "timeout" in text:
        return TransientError("The report form did not finish loading.")
    if "closed" in text or "target page" in text:
        return TransientError("The browser window was closed before the form was submitted.")
    return SubmissionError("The browser could not complete the form.")
