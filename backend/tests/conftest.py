import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("RUN_WORKER", "0")
    monkeypatch.setenv("FORM_URL", "http://127.0.0.1:9/")
    monkeypatch.setenv("CAPTCHA_STRATEGY", "manual")
    monkeypatch.setenv("MAX_ATTEMPTS", "3")
    from app.main import create_app

    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
