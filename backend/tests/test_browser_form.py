import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.browser_form import extract_confirmation, submit_form
from app.submitter import SubmissionError

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16

FORM = """<!DOCTYPE html>
<html>
<body>
<form action="/submit" method="post" enctype="multipart/form-data">
  <select id="submission_type" name="submission_type">
    <option value="domain">Domain</option>
    <option value="ip">IP</option>
    <option value="url">URL</option>
  </select>
  <input id="domain" name="domain">
  <input id="ip" name="ip">
  <input id="url" name="url">
  <input class="hp" name="company" tabindex="-1" autocomplete="off">
  <select id="threat_type" name="threat_type">
    <option value="Phishing">Phishing</option>
    <option value="Malware">Malware</option>
    <option value="Spam">Spam</option>
    <option value="Fraud / Scam">Fraud / Scam</option>
    <option value="Botnet C&amp;C">Botnet C&amp;C</option>
    <option value="Other">Other</option>
  </select>
  <textarea id="reason" name="reason"></textarea>
  <input id="attachment" name="attachment" type="file">
  <label><input name="accept_terms" type="checkbox" value="1"> I accept</label>
  <textarea name="g-recaptcha-response"></textarea>
  <button type="submit">Submit</button>
</form>
<script>
setTimeout(function () {
  document.querySelector('[name="g-recaptcha-response"]').value = "token-ok";
}, 400);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = FORM.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        self.server.posts.append(payload)
        if b"token-ok" in payload and b"phish.example" in payload:
            page = b"<html><body><p>Report received. CF-AB12CD34</p></body></html>"
        else:
            page = b"<html><body><p class='field-error'>Captcha missing</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, fmt, *args):
        return


def test_extract_confirmation_reads_the_cf_code():
    assert extract_confirmation("Report received. CF-AB12CD34") == "CF-AB12CD34"
    assert extract_confirmation("prefix CF-12AB34CD suffix") == "CF-12AB34CD"
    assert extract_confirmation("CF-short") is None
    assert extract_confirmation("cf-ab12cd34") is None
    assert extract_confirmation("") is None


def test_form_url_is_required():
    with pytest.raises(SubmissionError, match="FORM_URL"):
        submit_form("", {"submission_type": "domain", "threat_type": "phishing"}, headless=True, captcha_timeout_ms=1000, on_captcha=lambda: None)


def test_playwright_fills_local_form_and_reads_the_code(tmp_path):
    pytest.importorskip("playwright.sync_api")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.posts = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    evidence = Path(tmp_path) / "evidence.png"
    evidence.write_bytes(PNG)
    paused = []
    try:
        code = submit_form(
            f"http://127.0.0.1:{server.server_address[1]}/",
            {
                "submission_type": "domain",
                "threat_type": "phishing",
                "normalized": "phish.example",
                "reason": "Credential form impersonating a bank.",
                "evidence_path": str(evidence),
                "job_id": "local-fixture",
            },
            headless=True,
            captcha_timeout_ms=10000,
            on_captcha=lambda: paused.append("waiting"),
        )
    finally:
        server.shutdown()
        thread.join(timeout=3)
    assert paused == ["waiting"]
    assert code == "CF-AB12CD34"
    assert server.posts
    posted = server.posts[0]
    assert b"token-ok" in posted
    assert b"phish.example" in posted
    assert b"Phishing" in posted
    assert b"Credential form impersonating a bank." in posted
    assert b"evidence.png" in posted
