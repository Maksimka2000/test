"""Process settings. Limits and enums come from openapi.yaml, not from here."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv() -> None:
    """Fill unset variables from the repo .env. Existing values win."""
    candidates = (
        Path(__file__).resolve().parents[2] / ".env",
        Path.cwd() / ".env",
    )
    for path in candidates:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
        return


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    run_worker: bool
    worker_interval: float
    form_url: str
    browser_headless: bool
    captcha_timeout_seconds: float
    captcha_strategy: str
    max_attempts: int
    retry_base_seconds: float
    browser_no_sandbox: bool = False
    twocaptcha_api_key: str = ""
    recaptcha_sitekey: str = ""
    recaptcha_version: str = "v2"
    recaptcha_action: str = "verify"
    recaptcha_score: float = 0.7
    twocaptcha_polling_interval: float = 10
    twocaptcha_default_timeout: float = 120

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv()
        return cls(
            data_dir=Path(os.environ.get("DATA_DIR", "data")),
            run_worker=_flag("RUN_WORKER", True),
            worker_interval=float(os.environ.get("WORKER_INTERVAL", "0.5")),
            form_url=os.environ.get("FORM_URL", "").strip(),
            browser_headless=_flag("BROWSER_HEADLESS", False),
            browser_no_sandbox=_flag("BROWSER_NO_SANDBOX", False),
            captcha_timeout_seconds=float(os.environ.get("CAPTCHA_TIMEOUT_SECONDS", "600")),
            captcha_strategy=os.environ.get("CAPTCHA_STRATEGY", "manual").strip().lower() or "manual",
            max_attempts=max(1, int(os.environ.get("MAX_ATTEMPTS", "3"))),
            retry_base_seconds=float(os.environ.get("RETRY_BASE_SECONDS", "5")),
            twocaptcha_api_key=os.environ.get("TWOCAPTCHA_API_KEY", "").strip(),
            recaptcha_sitekey=os.environ.get("RECAPTCHA_SITEKEY", "").strip(),
            recaptcha_version=os.environ.get("RECAPTCHA_VERSION", "v2").strip().lower() or "v2",
            recaptcha_action=os.environ.get("RECAPTCHA_ACTION", "verify").strip() or "verify",
            recaptcha_score=float(os.environ.get("RECAPTCHA_SCORE", "0.7")),
            twocaptcha_polling_interval=float(os.environ.get("TWOCAPTCHA_POLLING_INTERVAL", "10")),
            twocaptcha_default_timeout=float(os.environ.get("TWOCAPTCHA_DEFAULT_TIMEOUT", "120")),
        )
