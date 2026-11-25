"""Captcha strategies. Manual waits for the operator. Auto asks 2captcha."""

from __future__ import annotations

import threading
import time

import logging

from app.submitter import SkipRequested, TransientError, WorkerStopping

logger = logging.getLogger(__name__)

PAGE_STATE = """
() => {
  const text = document.body ? document.body.innerText : "";
  if (/CF-[A-Z0-9]{8}/.test(text)) return "done";
  const field = document.querySelector('textarea[name="g-recaptcha-response"]');
  if (field && field.value.trim()) return "ready";
  return "";
}
"""

INSTALL_TOKEN = """
(token) => {
  const form = document.querySelector("form");
  let fields = document.querySelectorAll('textarea[name="g-recaptcha-response"]');
  if (!fields.length && form) {
    const created = document.createElement("textarea");
    created.name = "g-recaptcha-response";
    created.style.display = "none";
    form.appendChild(created);
    fields = document.querySelectorAll('textarea[name="g-recaptcha-response"]');
  }
  fields.forEach((field) => {
    field.value = token;
  });
  const widget = document.querySelector(".g-recaptcha");
  const callbackName = widget && widget.getAttribute("data-callback");
  if (callbackName && typeof window[callbackName] === "function") {
    window[callbackName](token);
  }
}
"""


class ManualCaptchaStrategy:
    """Block until the operator solves the captcha in the open browser window."""

    def handle(self, page, target, *, timeout_ms: int, skip_check, stop_check=None) -> None:
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        if stop_check is None:
            stop_check = lambda: False
        deadline = time.monotonic() + (timeout_ms / 1000)
        while True:
            if stop_check():
                raise WorkerStopping()
            if skip_check():
                raise SkipRequested()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransientError("The captcha was not solved in time.")
            slice_ms = max(1, int(min(0.5, remaining) * 1000))
            try:
                page.wait_for_function(PAGE_STATE, timeout=slice_ms)
            except PlaywrightTimeout:
                continue
            return


class AutoCaptchaStrategy:
    """Ask 2captcha for a token and write it into g-recaptcha-response."""

    def __init__(
        self,
        *,
        api_key: str,
        sitekey: str,
        page_url: str,
        version: str = "v2",
        action: str = "verify",
        score: float = 0.7,
        polling_interval: int = 10,
        default_timeout: int = 120,
        solver_factory=None,
    ) -> None:
        self.api_key = api_key
        self.sitekey = sitekey
        self.page_url = page_url
        self.version = version
        self.action = action
        self.score = score
        self.polling_interval = polling_interval
        self.default_timeout = default_timeout
        self.solver_factory = solver_factory

    def handle(self, page, target, *, timeout_ms: int, skip_check, stop_check=None) -> None:
        if stop_check is None:
            stop_check = lambda: False
        if stop_check():
            raise WorkerStopping()
        if skip_check():
            raise SkipRequested()
        token = self._solve(target, timeout_ms, skip_check, stop_check)
        if stop_check():
            raise WorkerStopping()
        if skip_check():
            raise SkipRequested()
        page.evaluate(INSTALL_TOKEN, token)

    def _solve(self, target, timeout_ms: int, skip_check, stop_check) -> str:
        timeout_s = max(1, int(timeout_ms / 1000))
        solver = self._make_solver(timeout_s)
        box: dict = {}
        target_name = target.get("normalized") if isinstance(target, dict) else target
        logger.info("asking 2captcha for a %s token for %s", self.version, target_name)

        def run() -> None:
            try:
                kwargs = {
                    "sitekey": self.sitekey,
                    "url": self.page_url,
                    "version": self.version,
                }
                if self.version == "v3":
                    kwargs["action"] = self.action
                    kwargs["score"] = self.score
                box["result"] = solver.recaptcha(**kwargs)
            except Exception as exc:
                box["error"] = exc

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        deadline = time.monotonic() + timeout_s
        while worker.is_alive():
            if stop_check():
                raise WorkerStopping()
            if skip_check():
                raise SkipRequested()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            worker.join(min(0.5, remaining))
        if stop_check():
            raise WorkerStopping()
        if skip_check():
            raise SkipRequested()
        error = box.get("error")
        if error is not None:
            raise TransientError("The captcha solver did not return a token.") from error
        if worker.is_alive():
            raise TransientError("The captcha was not solved in time.")
        result = box.get("result")
        code = result.get("code") if isinstance(result, dict) else None
        if not code or not str(code).strip():
            raise TransientError("The captcha solver did not return a token.")
        logger.info("2captcha returned a token for %s", target_name)
        return str(code).strip()

    def _make_solver(self, timeout_s: int):
        if self.solver_factory is not None:
            return self.solver_factory(timeout_s)
        from twocaptcha import TwoCaptcha

        return TwoCaptcha(
            self.api_key,
            server="2captcha.com",
            defaultTimeout=min(self.default_timeout, timeout_s),
            recaptchaTimeout=timeout_s,
            pollingInterval=self.polling_interval,
        )


def load_strategy(name: str, settings=None):
    """Return the strategy named in CAPTCHA_STRATEGY.

    Auto is built here and is not called. A missing key or site key stops the
    process before the first row, and does not spend a solve.
    """
    normalized = (name or "").strip().lower()
    if normalized == "manual":
        return ManualCaptchaStrategy()
    if normalized == "auto":
        if settings is None:
            from app.settings import Settings

            settings = Settings.from_env()
        missing = []
        if not settings.twocaptcha_api_key:
            missing.append("TWOCAPTCHA_API_KEY")
        if not settings.recaptcha_sitekey:
            missing.append("RECAPTCHA_SITEKEY")
        if not settings.form_url:
            missing.append("FORM_URL")
        if missing:
            raise RuntimeError("CAPTCHA_STRATEGY=auto needs " + ", ".join(missing) + ".")
        version = settings.recaptcha_version
        if version not in {"v2", "v3"}:
            raise RuntimeError(f"RECAPTCHA_VERSION must be v2 or v3, not {version!r}.")
        return AutoCaptchaStrategy(
            api_key=settings.twocaptcha_api_key,
            sitekey=settings.recaptcha_sitekey,
            page_url=settings.form_url,
            version=version,
            action=settings.recaptcha_action,
            score=settings.recaptcha_score,
            polling_interval=max(1, int(settings.twocaptcha_polling_interval)),
            default_timeout=max(1, int(settings.twocaptcha_default_timeout)),
        )
    raise RuntimeError(f"CAPTCHA_STRATEGY must be manual or auto, not {name!r}.")
