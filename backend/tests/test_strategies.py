import threading
import time
from pathlib import Path

import pytest

from app.settings import Settings
from app.strategies import AutoCaptchaStrategy, load_strategy
from app.submitter import SkipRequested, TransientError, WorkerStopping


def _settings(**overrides):
    values = dict(
        data_dir=Path("data"),
        run_worker=False,
        worker_interval=0.01,
        form_url="https://linkreclamatiogrwc.uk/",
        browser_headless=True,
        captcha_timeout_seconds=1,
        captcha_strategy="auto",
        max_attempts=3,
        retry_base_seconds=0,
        twocaptcha_api_key="test-key",
        recaptcha_sitekey="6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28",
        recaptcha_version="v2",
        recaptcha_action="verify",
        recaptcha_score=0.7,
    )
    values.update(overrides)
    return Settings(**values)


class _Page:
    def __init__(self):
        self.tokens = []

    def evaluate(self, script, token):
        self.tokens.append((script, token))


def test_auto_strategy_refuses_to_start_without_a_key():
    with pytest.raises(RuntimeError) as exc:
        load_strategy("auto", _settings(twocaptcha_api_key=""))
    assert str(exc.value) == "CAPTCHA_STRATEGY=auto needs TWOCAPTCHA_API_KEY."


def test_auto_strategy_loads_without_calling_the_solver():
    strategy = load_strategy("auto", _settings())
    assert isinstance(strategy, AutoCaptchaStrategy)
    assert strategy.version == "v2"
    assert strategy.page_url == "https://linkreclamatiogrwc.uk/"


def test_auto_v2_writes_the_solver_token_into_the_page():
    seen = {}

    class Solver:
        def recaptcha(self, **kwargs):
            seen.update(kwargs)
            return {"code": "token-from-solver"}

    page = _Page()
    strategy = AutoCaptchaStrategy(
        api_key="test-key",
        sitekey="site-key",
        page_url="https://linkreclamatiogrwc.uk/",
        version="v2",
        action="verify",
        score=0.7,
        solver_factory=lambda timeout_s: Solver(),
    )
    strategy.handle(page, {"normalized": "example.com"}, timeout_ms=5000, skip_check=lambda: False)
    assert seen == {
        "sitekey": "site-key",
        "url": "https://linkreclamatiogrwc.uk/",
        "version": "v2",
    }
    assert page.tokens == [(strategy_script(), "token-from-solver")]


def test_auto_v3_sends_action_and_score():
    seen = {}

    class Solver:
        def recaptcha(self, **kwargs):
            seen.update(kwargs)
            return {"code": "token-v3"}

    strategy = AutoCaptchaStrategy(
        api_key="test-key",
        sitekey="site-key",
        page_url="https://linkreclamatiogrwc.uk/",
        version="v3",
        action="verify",
        score=0.7,
        solver_factory=lambda timeout_s: Solver(),
    )
    strategy.handle(_Page(), {}, timeout_ms=5000, skip_check=lambda: False)
    assert seen["version"] == "v3"
    assert seen["action"] == "verify"
    assert seen["score"] == 0.7


def test_auto_skip_leaves_the_page_untouched():
    started = threading.Event()

    class Solver:
        def recaptcha(self, **kwargs):
            started.set()
            time.sleep(5)
            return {"code": "late"}

    page = _Page()
    strategy = AutoCaptchaStrategy(
        api_key="test-key",
        sitekey="site-key",
        page_url="https://linkreclamatiogrwc.uk/",
        solver_factory=lambda timeout_s: Solver(),
    )
    with pytest.raises(SkipRequested):
        strategy.handle(page, {}, timeout_ms=10000, skip_check=started.is_set)
    assert page.tokens == []


def test_auto_stop_does_not_call_the_solver():
    called = []

    class Solver:
        def recaptcha(self, **kwargs):
            called.append(kwargs)
            return {"code": "should-not-run"}

    strategy = AutoCaptchaStrategy(
        api_key="test-key",
        sitekey="site-key",
        page_url="https://linkreclamatiogrwc.uk/",
        solver_factory=lambda timeout_s: Solver(),
    )
    with pytest.raises(WorkerStopping):
        strategy.handle(
            _Page(),
            {"normalized": "phi.example"},
            timeout_ms=5000,
            skip_check=lambda: False,
            stop_check=lambda: True,
        )
    assert called == []


def test_solver_failure_is_a_retryable_error():
    class Solver:
        def recaptcha(self, **kwargs):
            raise RuntimeError("solver down")

    strategy = AutoCaptchaStrategy(
        api_key="test-key",
        sitekey="site-key",
        page_url="https://linkreclamatiogrwc.uk/",
        solver_factory=lambda timeout_s: Solver(),
    )
    with pytest.raises(TransientError) as exc:
        strategy.handle(_Page(), {}, timeout_ms=5000, skip_check=lambda: False)
    assert str(exc.value) == "The captcha solver did not return a token."
    assert "solver down" not in str(exc.value)


def strategy_script():
    from app.strategies import INSTALL_TOKEN

    return INSTALL_TOKEN
