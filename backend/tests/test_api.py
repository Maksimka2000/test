import yaml

from app.contract import spec_path
from app.settings import Settings
from app.strategies import ManualCaptchaStrategy
from app.submitter import BrowserUnavailable, SubmissionError, TransientError
from app.worker import backoff_seconds, process_available_once

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
PDF = b"%PDF-1.4\n%\n"


def submit(
    client,
    *,
    submission_type="domain",
    targets="phish.example\n",
    threat_type="phishing",
    reason="Credential form impersonating a bank.",
    filename="evidence.png",
    content=PNG,
    content_type="image/png",
):
    return client.post(
        "/jobs",
        data={
            "submission_type": submission_type,
            "targets": targets,
            "threat_type": threat_type,
            "reason": reason,
        },
        files={"evidence": (filename, content, content_type)},
    )


def messages(response):
    body = response.json()
    return [item["msg"] if isinstance(item, dict) else item for item in body["detail"]]


def assert_job_shape(body):
    assert set(body) == {
        "id",
        "submission_type",
        "threat_type",
        "reason",
        "evidence",
        "created_at",
        "paused",
        "max_attempts",
        "summary",
        "targets",
    }
    assert set(body["evidence"]) == {"filename", "media_type", "size_bytes"}
    assert set(body["summary"]) == {
        "total",
        "pending",
        "running",
        "awaiting_captcha",
        "retrying",
        "submitted",
        "failed",
        "skipped",
        "duplicates_removed",
    }
    summary = body["summary"]
    assert (
        summary["pending"]
        + summary["running"]
        + summary["awaiting_captcha"]
        + summary["retrying"]
        + summary["submitted"]
        + summary["failed"]
        + summary["skipped"]
        == summary["total"]
    )
    assert body["paused"] is False
    assert body["max_attempts"] == 3
    assert body["created_at"].endswith("Z")
    for target in body["targets"]:
        assert set(target) == {
            "id",
            "position",
            "input",
            "value",
            "status",
            "attempts",
            "error",
            "confirmation_code",
        }
        assert target["status"] in {
            "pending",
            "running",
            "awaiting_captcha",
            "retrying",
            "submitted",
            "failed",
            "skipped",
        }


def rejecting(values, seen=None):
    blocked = set(values)

    def submit(row, on_captcha):
        on_captcha()
        if seen is not None:
            seen.append(row["normalized"])
        if row["normalized"] in blocked:
            raise SubmissionError("upstream rejected the report")
        return "CF-AB12CD34"

    return submit


def exploding(row, on_captcha):
    on_captcha()
    raise RuntimeError("secret /tmp/should-not-leak")


def test_health_and_served_contract_match_the_file(client):
    spec = yaml.safe_load(spec_path().read_text(encoding="utf-8"))
    assert client.get("/openapi.json").json() == spec
    assert set(spec["paths"]) == {
        "/queue",
        "/queue/retry-failed",
        "/jobs",
        "/jobs/{id}",
        "/jobs/{id}/retry",
        "/jobs/{id}/retry-failed",
        "/jobs/{id}/pause",
        "/jobs/{id}/resume",
        "/targets/{id}/skip",
        "/targets/{id}/retry",
        "/health",
    }

    health = client.get("/health").json()
    contract = client.app.state.contract
    assert health["status"] == "ok"
    assert health["limits"]["maxBatchSize"] == contract.max_batch_size
    assert health["limits"]["maxEvidenceBytes"] == contract.max_evidence_bytes
    assert health["limits"]["maxReasonLength"] == contract.max_reason_length
    assert health["limits"]["maxTargetsChars"] == contract.max_targets_chars
    assert health["enums"]["submissionType"] == list(contract.submission_types)
    assert health["enums"]["threatType"] == list(contract.threat_types)
    assert health["captcha_strategy"] == "manual"
    assert client.app.state.settings.run_worker is False


def test_queue_lists_every_target_newest_batch_first(client):
    submit(client, targets="older.example\n")
    newer = submit(client, targets="newer.example\nlater.example\n")
    queue = client.get("/queue")
    assert queue.status_code == 200, queue.text
    body = queue.json()
    values = [item["value"] for item in body["targets"]]
    assert values[:2] == ["newer.example", "later.example"]
    assert values.index("newer.example") < values.index("older.example")
    top = body["targets"][0]
    assert top["job_id"] == newer.json()["id"]
    assert top["timeout_seconds"] is None
    assert set(body["summary"]) == {
        "total",
        "pending",
        "running",
        "awaiting_captcha",
        "retrying",
        "submitted",
        "failed",
        "skipped",
        "duplicates_removed",
    }
    client.app.state.store._set_status(top["id"], "awaiting_captcha", None, None)
    waiting = client.get("/queue").json()
    row = next(item for item in waiting["targets"] if item["id"] == top["id"])
    assert waiting["captcha_timeout_seconds"] - 2 <= row["timeout_seconds"] <= waiting["captcha_timeout_seconds"]


def test_create_get_and_dedupe(client):
    response = submit(
        client,
        targets="Example.COM.\nexample.com\nlogin.phish.example\n",
        filename="../../etc/passwd.PNG",
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert_job_shape(body)
    assert response.headers["location"] == f"/jobs/{body['id']}"
    assert body["evidence"] == {
        "filename": "passwd.png",
        "media_type": "image/png",
        "size_bytes": len(PNG),
    }
    assert body["summary"]["total"] == 2
    assert body["summary"]["duplicates_removed"] == 1
    assert body["summary"]["pending"] == 2
    assert [target["value"] for target in body["targets"]] == ["example.com", "login.phish.example"]
    assert body["targets"][0]["input"] == "Example.COM."
    assert all(
        target["status"] == "pending" and target["attempts"] == 0 and target["confirmation_code"] is None
        for target in body["targets"]
    )
    assert client.get(f"/jobs/{body['id']}").json() == body
    assert client.get(f"/jobs/{body['id'].upper()}").json() == body


def test_invalid_line_and_bad_file_store_nothing(client):
    response = submit(client, targets="phish.example\nhttps://phish.example/login\n")
    assert response.status_code == 422
    assert messages(response) == ["Not a domain. This value looks like a URL."]
    assert set(response.json()["detail"][0]) == {"loc", "msg", "type"}

    response = submit(client, filename="notes.pdf", content=PNG, content_type="application/pdf")
    assert response.status_code == 422
    assert "File extension does not match the file contents." in messages(response)

    response = submit(client, content=b"not an image", content_type="image/png")
    assert response.status_code == 422
    assert "Evidence must be a JPEG, PNG, or PDF." in messages(response)

    assert client.app.state.store.count_jobs() == 0
    assert list(client.app.state.store.evidence_dir.iterdir()) == []


def test_file_size_reason_and_batch_limits(client):
    contract = client.app.state.contract
    exact = PNG + b"0" * (contract.max_evidence_bytes - len(PNG))
    response = submit(client, content=exact)
    assert response.status_code == 201, response.text
    assert response.json()["evidence"]["size_bytes"] == contract.max_evidence_bytes

    oversized = exact + b"0"
    response = submit(client, content=oversized)
    assert response.status_code == 422
    assert messages(response) == [f"Evidence file exceeds {contract.max_evidence_bytes} bytes."]

    response = submit(client, reason="x" * (contract.max_reason_length + 1))
    assert response.status_code == 422
    assert any("exceeds" in message for message in messages(response))

    too_many = "\n".join(f"h{index}.example" for index in range(contract.max_batch_size + 1))
    response = submit(client, targets=too_many)
    assert response.status_code == 422
    assert str(contract.max_batch_size) in messages(response)[0]
    assert client.app.state.store.count_jobs() == 1


def test_missing_fields_and_content_type(client):
    response = client.post("/jobs", json={"submission_type": "domain"})
    assert response.status_code == 415
    assert response.json() == {"detail": "Content-Type must be multipart/form-data."}

    response = client.post(
        "/jobs",
        data={"submission_type": "domain"},
        files={"evidence": ("e.png", PNG, "image/png")},
    )
    assert response.status_code == 422
    assert messages(response).count("Field required.") == 3

    response = submit(client, submission_type="hostname", threat_type="Phishing")
    assert response.status_code == 422
    assert "Submission type must be one of: domain, ip, url." in messages(response)
    assert "Threat type must be one of: phishing, malware, scam, spam, c2, other." in messages(response)


def test_ip_and_url_jobs_round_trip(client):
    response = submit(
        client,
        submission_type="ip",
        targets="2001:0db8::1\n192.0.2.8\n",
        filename="capture.jpg",
        content=JPEG,
        content_type="image/jpg",
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert [target["value"] for target in body["targets"]] == ["2001:db8::1", "192.0.2.8"]
    assert body["evidence"]["media_type"] == "image/jpeg"

    response = submit(
        client,
        submission_type="url",
        targets="HTTPS://Phish.Example/login#token\nhttps://phish.example/login\n",
        filename="page.pdf",
        content=PDF,
        content_type="application/pdf",
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["summary"]["duplicates_removed"] == 1
    assert body["targets"][0]["value"] == "https://phish.example/login"
    assert body["targets"][0]["input"] == "HTTPS://Phish.Example/login#token"


def test_unknown_and_malformed_ids(client):
    missing = "11111111-1111-4111-8111-111111111111"
    assert client.get(f"/jobs/{missing}").json() == {"detail": "Job not found."}
    assert client.get(f"/jobs/{missing}").status_code == 404
    retry = client.post(f"/jobs/{missing}/retry")
    assert retry.status_code == 404
    assert retry.json()["detail"] == "Job not found."

    bad = client.get("/jobs/not-a-uuid")
    assert bad.status_code == 422
    assert bad.json()["detail"][0]["msg"] == "Job id must be a UUID."
    assert client.post("/jobs/not-a-uuid/retry").status_code == 422


def test_worker_submits_one_row_at_a_time_and_retry_is_selective(client):
    response = submit(client, targets="good.example\nbad.example\nkept.example\n")
    assert response.status_code == 201, response.text
    job_id = response.json()["id"]
    store = client.app.state.store
    paused = []

    def submit_row(row, on_captcha):
        on_captcha()
        current = client.get(f"/jobs/{job_id}").json()
        match = next(target for target in current["targets"] if target["value"] == row["normalized"])
        paused.append(match["status"])
        if row["normalized"] == "bad.example":
            raise SubmissionError("upstream rejected the report")
        return "CF-AB12CD34"

    assert store.process_next(submit_row) is True
    assert store.process_next(submit_row) is True
    assert store.process_next(submit_row) is True
    assert store.process_next(submit_row) is False
    assert paused == ["awaiting_captcha", "awaiting_captcha", "awaiting_captcha"]
    body = client.get(f"/jobs/{job_id}").json()
    by_value = {target["value"]: target for target in body["targets"]}
    assert by_value["good.example"]["status"] == "submitted"
    assert by_value["good.example"]["attempts"] == 1
    assert by_value["good.example"]["error"] is None
    assert by_value["good.example"]["confirmation_code"] == "CF-AB12CD34"
    assert by_value["kept.example"]["status"] == "submitted"
    assert by_value["bad.example"]["status"] == "failed"
    assert by_value["bad.example"]["attempts"] == 1
    assert by_value["bad.example"]["error"] == "upstream rejected the report"
    assert by_value["bad.example"]["confirmation_code"] is None
    assert store.count_submissions() == 2
    assert body["summary"] == {
        "total": 3,
        "pending": 0,
        "running": 0,
        "awaiting_captcha": 0,
        "retrying": 0,
        "submitted": 2,
        "failed": 1,
        "skipped": 0,
        "duplicates_removed": 0,
    }

    assert store.process_next(rejecting({"bad.example"})) is False
    assert store.count_submissions() == 2

    empty = client.post(f"/jobs/{job_id}/retry")
    assert empty.status_code == 200, empty.text
    retried = empty.json()
    by_value = {target["value"]: target for target in retried["targets"]}
    assert by_value["bad.example"]["status"] == "pending"
    assert by_value["bad.example"]["attempts"] == 1
    assert by_value["bad.example"]["error"] is None
    assert by_value["bad.example"]["confirmation_code"] is None
    assert by_value["good.example"]["status"] == "submitted"
    assert by_value["good.example"]["attempts"] == 1
    assert by_value["kept.example"]["status"] == "submitted"

    assert store.process_next(rejecting(set())) is True
    finished = client.get(f"/jobs/{job_id}").json()
    by_value = {target["value"]: target for target in finished["targets"]}
    assert by_value["bad.example"]["status"] == "submitted"
    assert by_value["bad.example"]["confirmation_code"] == "CF-AB12CD34"
    assert by_value["bad.example"]["attempts"] == 2
    assert by_value["good.example"]["attempts"] == 1
    assert store.count_submissions() == 3

    nothing = client.post(f"/jobs/{job_id}/retry")
    assert nothing.status_code == 409
    assert nothing.json() == {"detail": "No failed targets to re-queue."}
    assert client.get(f"/jobs/{job_id}").json()["targets"] == finished["targets"]


def test_queue_takes_the_newest_batch_first(client):
    first = submit(client, targets="a.example\nb.example\n")
    second = submit(client, targets="c.example\n")
    assert first.status_code == 201 and second.status_code == 201
    order = []

    def submit_row(row, on_captcha):
        on_captcha()
        order.append(row["normalized"])
        return "CF-ORDER123"

    store = client.app.state.store
    while store.process_next(submit_row):
        pass
    assert order == ["c.example", "a.example", "b.example"]


def test_restart_returns_stuck_rows_to_pending(client):
    response = submit(
        client,
        targets="running.example\nwaiting.example\nretrying.example\ndone.example\nbroken.example\n",
    )
    job_id = response.json()["id"]
    store = client.app.state.store
    store._conn.execute(
        "UPDATE targets SET status = 'running', attempts = 2 WHERE normalized = ?",
        ("running.example",),
    )
    store._conn.execute(
        "UPDATE targets SET status = 'awaiting_captcha', attempts = 1 WHERE normalized = ?",
        ("waiting.example",),
    )
    store._conn.execute(
        "UPDATE targets SET status = 'retrying', attempts = 1 WHERE normalized = ?",
        ("retrying.example",),
    )
    store._conn.execute(
        "UPDATE targets SET status = 'submitted', confirmation_code = 'CF-KEEP1234' WHERE normalized = ?",
        ("done.example",),
    )
    store._conn.execute(
        "UPDATE targets SET status = 'failed', error = 'kept' WHERE normalized = ?",
        ("broken.example",),
    )
    assert store.reset_interrupted() == 3
    by_value = {target["value"]: target for target in client.get(f"/jobs/{job_id}").json()["targets"]}
    assert by_value["running.example"]["status"] == "pending"
    assert by_value["running.example"]["attempts"] == 2
    assert by_value["running.example"]["error"] is None
    assert by_value["waiting.example"]["status"] == "pending"
    assert by_value["waiting.example"]["attempts"] == 1
    assert by_value["retrying.example"]["status"] == "pending"
    assert by_value["retrying.example"]["attempts"] == 1
    assert by_value["done.example"]["status"] == "submitted"
    assert by_value["done.example"]["confirmation_code"] == "CF-KEEP1234"
    assert by_value["broken.example"]["status"] == "failed"
    assert by_value["broken.example"]["error"] == "kept"


def test_browser_unavailable_releases_the_row(client):
    response = submit(client, targets="phish.example\n")
    job_id = response.json()["id"]
    store = client.app.state.store

    def submit_row(row, on_captcha):
        raise BrowserUnavailable("no display")

    try:
        store.process_next(submit_row)
    except BrowserUnavailable:
        released = True
    else:
        released = False
    assert released is True
    target = client.get(f"/jobs/{job_id}").json()["targets"][0]
    assert target["status"] == "pending"
    assert target["attempts"] == 0
    assert store.count_submissions() == 0


def test_unexpected_submitter_errors_are_not_echoed(client):
    response = submit(client, targets="phish.example\n")
    job_id = response.json()["id"]
    client.app.state.store.process_next(exploding)
    body = client.get(f"/jobs/{job_id}").json()
    assert body["targets"][0]["status"] == "failed"
    assert body["targets"][0]["error"] == "The form could not be submitted."
    assert "secret" not in response.text
    assert "secret" not in client.get(f"/jobs/{job_id}").text
    assert client.app.state.store.count_submissions() == 0


def test_backoff_is_exponential():
    assert backoff_seconds(1, 5) == 5
    assert backoff_seconds(2, 5) == 15
    assert backoff_seconds(3, 5) == 45


def test_transient_failure_retries_the_same_row(client):
    response = submit(client, targets="flaky.example\nnext.example\n")
    job_id = response.json()["id"]
    seen = []

    def submit_row(row, on_captcha, skip_check):
        on_captcha()
        seen.append((row["normalized"], row["attempts"], skip_check()))
        if row["normalized"] == "flaky.example" and row["attempts"] < 3:
            raise TransientError("The report form did not finish loading.")
        return "CF-AB12CD34"

    settings = _settings(client)
    store = client.app.state.store
    assert process_available_once(store, settings, ManualCaptchaStrategy(), submit_row) is True
    body = client.get(f"/jobs/{job_id}").json()
    by_value = {target["value"]: target for target in body["targets"]}
    assert by_value["flaky.example"]["status"] == "submitted"
    assert by_value["flaky.example"]["attempts"] == 3
    assert by_value["flaky.example"]["confirmation_code"] == "CF-AB12CD34"
    assert by_value["next.example"]["status"] == "pending"
    assert by_value["next.example"]["attempts"] == 0
    assert [item[0] for item in seen] == ["flaky.example", "flaky.example", "flaky.example"]


def test_permanent_error_is_not_retried(client):
    response = submit(client, targets="bad.example\n")
    calls = {"n": 0}

    def submit_row(row, on_captcha, skip_check):
        calls["n"] += 1
        raise SubmissionError("The form no longer has the target field.")

    assert process_available_once(client.app.state.store, _settings(client), ManualCaptchaStrategy(), submit_row)
    target = client.get(f"/jobs/{response.json()['id']}").json()["targets"][0]
    assert calls["n"] == 1
    assert target["status"] == "failed"
    assert target["attempts"] == 1
    assert target["error"] == "The form no longer has the target field."


def test_skip_pending_and_pause_and_retry(client):
    response = submit(client, targets="first.example\nsecond.example\n")
    job_id = response.json()["id"]
    body = response.json()
    first = body["targets"][0]

    skipped = client.post(f"/targets/{first['id']}/skip")
    assert skipped.status_code == 200, skipped.text
    by_value = {target["value"]: target for target in skipped.json()["targets"]}
    assert by_value["first.example"]["status"] == "skipped"

    paused = client.post(f"/jobs/{job_id}/pause")
    assert paused.status_code == 200
    assert paused.json()["paused"] is True
    assert client.app.state.store.claim_next() is None

    resumed = client.post(f"/jobs/{job_id}/resume")
    assert resumed.json()["paused"] is False

    def submit_row(row, on_captcha, skip_check):
        on_captcha()
        assert row["normalized"] == "second.example"
        return "CF-AB12CD34"

    assert process_available_once(client.app.state.store, _settings(client), ManualCaptchaStrategy(), submit_row)
    finished = client.get(f"/jobs/{job_id}").json()
    by_value = {target["value"]: target for target in finished["targets"]}
    assert by_value["second.example"]["status"] == "submitted"
    assert by_value["first.example"]["status"] == "skipped"

    again = client.post(f"/targets/{first['id']}/retry")
    assert again.status_code == 200, again.text
    by_value = {target["value"]: target for target in again.json()["targets"]}
    assert by_value["first.example"]["status"] == "pending"
    assert by_value["first.example"]["attempts"] == 0

    missing = client.post("/targets/999999/skip")
    assert missing.status_code == 404
    blocked = client.post(f"/targets/{by_value['second.example']['id']}/skip")
    assert blocked.status_code == 409


def _settings(client):
    current = client.app.state.settings
    return Settings(
        data_dir=current.data_dir,
        run_worker=False,
        worker_interval=0.01,
        form_url="http://127.0.0.1:9/",
        browser_headless=True,
        captcha_timeout_seconds=1,
        captcha_strategy="manual",
        max_attempts=3,
        retry_base_seconds=0,
    )
