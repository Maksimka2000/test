import pytest

from app.contract import load_contract
from app.status import STATUSES
from app.validation import (
    extension_types,
    normalize_domain,
    normalize_ip,
    normalize_url,
    signature_types,
    validate_submission,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"


@pytest.fixture(scope="module")
def contract():
    return load_contract()


def _submit(contract, **overrides):
    payload = {
        "submission_type": "domain",
        "targets": "phish.example\n",
        "threat_type": "phishing",
        "reason": "Credential form impersonating a bank.",
        "filename": "landing.png",
        "declared_type": "image/png",
        "evidence": PNG,
        "evidence_error": None,
    }
    payload.update(overrides)
    return validate_submission(contract, **payload)


def test_contract_enums_and_sniffers_stay_aligned(contract):
    assert contract.statuses == STATUSES
    assert signature_types() == set(contract.evidence_types)
    assert extension_types() == set(contract.evidence_types)
    assert contract.max_batch_size == 500
    assert contract.max_evidence_bytes == 2097152


def test_domain_normalization_and_dedupe(contract):
    parsed, errors = _submit(
        contract,
        targets="Example.COM.\nexample.com\nmünchen.example\nexample.com.\n",
    )
    assert errors == []
    assert parsed.duplicates_removed == 2
    assert [target.normalized for target in parsed.targets] == [
        "example.com",
        "münchen.example".encode("idna").decode("ascii"),
    ]
    assert parsed.targets[0].original == "Example.COM."
    assert [target.line for target in parsed.targets] == [1, 3]


def test_ip_normalization_and_dedupe(contract):
    parsed, errors = _submit(
        contract,
        submission_type="ip",
        targets="2001:0db8:0000:0000:0000:0000:0000:0001\n[2001:db8::1]\n192.0.2.10\n",
    )
    assert errors == []
    assert [target.normalized for target in parsed.targets] == ["2001:db8::1", "192.0.2.10"]
    assert parsed.duplicates_removed == 1


def test_url_normalization_and_dedupe(contract):
    parsed, errors = _submit(
        contract,
        submission_type="url",
        targets=(
            "HTTPS://Example.COM:443/a#frag\n"
            "https://example.com/a\n"
            "http://[2001:DB8::1]:8080/a\n"
            "http://example.com:80\n"
        ),
    )
    assert errors == []
    assert [target.normalized for target in parsed.targets] == [
        "https://example.com/a",
        "http://[2001:db8::1]:8080/a",
        "http://example.com/",
    ]
    assert parsed.duplicates_removed == 1


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("domain", "https://phish.example/login"),
        ("domain", "203.0.113.10"),
        ("domain", "phish.example:443"),
        ("domain", "localhost"),
        ("domain", "bad_host.example"),
        ("domain", "example.com.."),
        ("ip", "https://203.0.113.10/"),
        ("ip", "203.0.113.10:80"),
        ("ip", "phish.example"),
        ("ip", "fe80::1%eth0"),
        ("url", "phish.example"),
        ("url", "ftp://phish.example/a"),
        ("url", "https://user:pass@phish.example/a"),
        ("url", "http://"),
        ("url", "javascript:alert(1)"),
    ],
)
def test_rejects_mistyped_targets(contract, kind, value):
    with pytest.raises(ValueError):
        if kind == "domain":
            normalize_domain(value)
        elif kind == "ip":
            normalize_ip(value)
        else:
            normalize_url(value, contract)


def test_invalid_lines_name_their_original_numbers_and_block_the_batch(contract):
    parsed, errors = _submit(contract, targets="\nphish.example\nhttps://phish.example/a\n203.0.113.5\n")
    assert parsed is None
    assert [error["loc"] for error in errors] == [["body", "targets", 3], ["body", "targets", 4]]
    assert errors[0]["msg"] == "Not a domain. This value looks like a URL."
    assert errors[1]["msg"] == "Not a domain. This value is an IP address."
    assert errors[0].keys() == {"loc", "msg", "type"}


def test_bad_submission_type_does_not_pretend_to_typecheck_lines(contract):
    parsed, errors = _submit(contract, submission_type="hostname", targets="not a domain")
    assert parsed is None
    assert [error["msg"] for error in errors] == ["Submission type must be one of: domain, ip, url."]


def test_blank_batch_and_cap_and_reason(contract):
    parsed, errors = _submit(contract, targets="\n   \n")
    assert parsed is None
    assert errors[0]["msg"] == "Provide at least one target, one per line."

    too_many = "\n".join(f"h{index}.example" for index in range(contract.max_batch_size + 1))
    parsed, errors = _submit(contract, targets=too_many)
    assert parsed is None
    assert "500" in errors[0]["msg"]
    assert str(contract.max_batch_size + 1) in errors[0]["msg"]

    parsed, errors = _submit(contract, reason="   ")
    assert parsed is None
    assert any(error["msg"] == "Reason is required." for error in errors)

    parsed, errors = _submit(contract, reason="x" * (contract.max_reason_length + 1))
    assert parsed is None
    assert any("exceeds" in error["msg"] for error in errors)

    parsed, errors = _submit(contract, targets="x" * (contract.max_targets_chars + 1))
    assert parsed is None
    assert any(error["type"] == "value_error.targets_length" for error in errors)


def test_evidence_rules(contract):
    cases = [
        ({"filename": "shot.PNG", "declared_type": "image/png", "evidence": PNG}, "shot.png", "image/png"),
        ({"filename": "shot.jpg", "declared_type": "image/jpg", "evidence": JPEG}, "shot.jpg", "image/jpeg"),
        ({"filename": "shot.jpeg", "declared_type": "image/jpeg", "evidence": JPEG}, "shot.jpeg", "image/jpeg"),
        ({"filename": "note.pdf", "declared_type": "application/pdf", "evidence": PDF}, "note.pdf", "application/pdf"),
        (
            {"filename": "shot.png", "declared_type": "application/octet-stream", "evidence": PNG},
            "shot.png",
            "image/png",
        ),
        (
            {"filename": "shot.png", "declared_type": "image/png; charset=binary", "evidence": PNG},
            "shot.png",
            "image/png",
        ),
    ]
    for overrides, filename, media_type in cases:
        parsed, errors = _submit(contract, **overrides)
        assert errors == [], overrides
        assert parsed.evidence.filename == filename
        assert parsed.evidence.media_type == media_type

    parsed, errors = _submit(contract, filename="../../etc/passwd.png")
    assert errors == []
    assert parsed.evidence.filename == "passwd.png"

    failures = [
        ({"evidence": b"GIF89a" + PNG, "filename": "shot.png"}, "Evidence must be a JPEG, PNG, or PDF."),
        ({"evidence": JPEG, "filename": "shot.png"}, "File extension does not match the file contents."),
        ({"evidence": b"GIF89a", "filename": "shot.gif"}, "Evidence filename must end in .jpg, .jpeg, .png, or .pdf."),
        ({"evidence": b"", "filename": "shot.png"}, "Evidence file is empty."),
        ({"evidence": b"", "filename": ""}, "Evidence file is required."),
        ({"evidence": PNG, "declared_type": "text/plain"}, "Declared Content-Type does not match the file contents."),
        ({"filename": ".png", "evidence": PNG}, "Evidence filename is required."),
    ]
    for overrides, message in failures:
        parsed, errors = _submit(contract, **overrides)
        assert parsed is None
        assert message in [error["msg"] for error in errors]


def test_exact_size_boundary_is_left_to_the_reader(contract):
    assert contract.max_evidence_bytes == contract.spec["info"]["x-limits"]["maxEvidenceBytes"]


def test_non_default_ports_are_preserved():
    contract = load_contract()
    assert normalize_url("http://example.com:443/a", contract) == "http://example.com:443/a"
    assert normalize_url("https://example.com:80/a", contract) == "https://example.com:80/a"
    assert normalize_url("http://localhost/a", contract) == "http://localhost/a"
