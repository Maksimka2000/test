"""Check a job against the OpenAPI contract before anything is stored."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from app.contract import Contract
from app.errors import field_error

_LABEL = re.compile(r"[a-z0-9-]+")
_SIGNATURES = (
    ("image/jpeg", b"\xff\xd8\xff"),
    ("image/png", b"\x89PNG\r\n\x1a\n"),
    ("application/pdf", b"%PDF-"),
)
_EXTENSIONS = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".pdf": "application/pdf",
}


@dataclass(frozen=True)
class ParsedTarget:
    line: int
    original: str
    normalized: str


@dataclass(frozen=True)
class ParsedEvidence:
    filename: str
    media_type: str
    size_bytes: int
    content: bytes


@dataclass(frozen=True)
class ParsedSubmission:
    submission_type: str
    threat_type: str
    reason: str
    targets: tuple
    duplicates_removed: int
    evidence: ParsedEvidence


def signature_types() -> set:
    return {media_type for media_type, _signature in _SIGNATURES}


def extension_types() -> set:
    return set(_EXTENSIONS.values())


def validate_submission(
    contract: Contract,
    *,
    submission_type: str | None,
    targets: str | None,
    threat_type: str | None,
    reason: str | None,
    filename: str | None,
    declared_type: str | None,
    evidence: bytes | None,
    evidence_error: dict | None = None,
) -> tuple[ParsedSubmission | None, list]:
    errors = []

    type_error, clean_type = _choice(
        submission_type,
        contract.submission_types,
        "submission_type",
        "Submission type",
    )
    if type_error:
        errors.append(type_error)

    threat_error, clean_threat = _choice(
        threat_type,
        contract.threat_types,
        "threat_type",
        "Threat type",
    )
    if threat_error:
        errors.append(threat_error)

    reason_error, clean_reason = _reason(reason, contract)
    if reason_error:
        errors.append(reason_error)

    parsed_targets: list[ParsedTarget] = []
    duplicates_removed = 0
    if targets is None:
        errors.append(field_error(("body", "targets"), "Field required.", "missing"))
    else:
        structural = _target_structure(targets, contract)
        if structural:
            errors.append(structural)
        elif clean_type is not None:
            line_errors, parsed_targets, duplicates_removed = _typecheck_targets(
                targets, clean_type, contract
            )
            errors.extend(line_errors)

    evidence_errors, parsed_evidence = _evidence(
        contract,
        filename=filename,
        declared_type=declared_type,
        content=evidence,
        evidence_error=evidence_error,
    )
    errors.extend(evidence_errors)

    if errors or clean_type is None or clean_threat is None or clean_reason is None:
        return None, errors
    if parsed_evidence is None:
        return None, errors
    return (
        ParsedSubmission(
            submission_type=clean_type,
            threat_type=clean_threat,
            reason=clean_reason,
            targets=tuple(parsed_targets),
            duplicates_removed=duplicates_removed,
            evidence=parsed_evidence,
        ),
        [],
    )


def _choice(value: str | None, allowed: tuple, field: str, label: str) -> tuple[dict | None, str | None]:
    if value is None:
        return field_error(("body", field), "Field required.", "missing"), None
    cleaned = value.strip()
    if cleaned not in allowed:
        joined = ", ".join(allowed)
        return (
            field_error(
                ("body", field),
                f"{label} must be one of: {joined}.",
                "value_error.enum",
            ),
            None,
        )
    return None, cleaned


def _reason(value: str | None, contract: Contract) -> tuple[dict | None, str | None]:
    if value is None:
        return field_error(("body", "reason"), "Field required.", "missing"), None
    if "\x00" in value:
        return field_error(("body", "reason"), "Reason contains a null character.", "value_error.reason"), None
    cleaned = value.strip()
    if not cleaned:
        return field_error(("body", "reason"), "Reason is required.", "value_error.reason"), None
    if len(cleaned) > contract.max_reason_length:
        return (
            field_error(
                ("body", "reason"),
                f"Reason exceeds {contract.max_reason_length} characters.",
                "value_error.reason",
            ),
            None,
        )
    return None, cleaned


def _target_structure(text: str, contract: Contract) -> dict | None:
    if "\x00" in text:
        return field_error(("body", "targets"), "Targets contain a null character.", "value_error.targets")
    if len(text) > contract.max_targets_chars:
        return field_error(
            ("body", "targets"),
            f"Targets text exceeds {contract.max_targets_chars} characters.",
            "value_error.targets_length",
        )
    lines = _nonempty_lines(text)
    if not lines:
        return field_error(
            ("body", "targets"),
            "Provide at least one target, one per line.",
            "value_error.targets_empty",
        )
    if len(lines) > contract.max_batch_size:
        return field_error(
            ("body", "targets"),
            (
                f"At most {contract.max_batch_size} targets are allowed per job; "
                f"received {len(lines)} non-empty lines."
            ),
            "value_error.batch_size",
        )
    return None


def _typecheck_targets(text: str, submission_type: str, contract: Contract):
    errors = []
    parsed = []
    for line_no, stripped in _nonempty_lines(text):
        try:
            normalized = normalize_target(submission_type, stripped, contract)
        except ValueError as exc:
            errors.append(field_error(("body", "targets", line_no), str(exc), "value_error.target"))
        else:
            parsed.append(ParsedTarget(line_no, stripped, normalized))
    if errors:
        return errors, [], 0

    unique = []
    seen = set()
    for item in parsed:
        if item.normalized in seen:
            continue
        seen.add(item.normalized)
        unique.append(item)
    return [], unique, len(parsed) - len(unique)


def _nonempty_lines(text: str) -> list:
    lines = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped:
            lines.append((line_no, stripped))
    return lines


def normalize_target(submission_type: str, value: str, contract: Contract) -> str:
    if submission_type == "domain":
        return normalize_domain(value)
    if submission_type == "ip":
        return normalize_ip(value)
    if submission_type == "url":
        return normalize_url(value, contract)
    raise ValueError("Submission type must be one of: domain, ip, url.")


def normalize_domain(value: str) -> str:
    if _has_junk(value):
        raise ValueError("Not a domain. Use a hostname such as phish.example.")
    if _as_ip(value) is not None:
        raise ValueError("Not a domain. This value is an IP address.")
    if "://" in value or "/" in value or "?" in value or "#" in value or "@" in value:
        raise ValueError("Not a domain. This value looks like a URL.")
    if ":" in value:
        raise ValueError("Not a domain. Remove the port, or choose the url submission type.")
    try:
        host, _is_ip = canonical_host(value, require_fqdn=True)
    except ValueError as exc:
        message = str(exc)
        if message == "Use a hostname with at least two labels, such as phish.example.":
            raise ValueError(f"Not a domain. {message}") from exc
        raise ValueError("Not a domain. Use a hostname such as phish.example.") from exc
    return host


def normalize_ip(value: str) -> str:
    if _has_junk(value):
        raise ValueError("Not an IP address. Use an IPv4 or IPv6 address without a port.")
    if "://" in value or "/" in value:
        raise ValueError("Not an IP address. This value looks like a URL.")
    parsed = _as_ip(value)
    if parsed is None:
        raise ValueError("Not an IP address. Use an IPv4 or IPv6 address without a port.")
    return parsed.compressed


def normalize_url(value: str, contract: Contract) -> str:
    if len(value) > contract.max_url_length:
        raise ValueError(f"Not a URL. URLs must be at most {contract.max_url_length} characters.")
    if _has_junk(value):
        raise ValueError("Not a URL. Remove spaces and backslashes.")
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Not a URL. Start with http:// or https://.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Not a URL. Remove the username and password.")
    if not parts.hostname:
        raise ValueError("Not a URL. Include a host.")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Not a URL. The port is invalid.") from exc
    if port == 0:
        raise ValueError("Not a URL. The port is invalid.")
    try:
        host, is_ip = canonical_host(parts.hostname, require_fqdn=False)
    except ValueError as exc:
        raise ValueError("Not a URL. The hostname is not valid.") from exc
    netloc = f"[{host}]" if is_ip and ":" in host else host
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def canonical_host(host: str, *, require_fqdn: bool) -> tuple:
    candidate = host.strip()
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate:
        raise ValueError("The hostname is not valid.")
    parsed_ip = _as_ip(candidate)
    if parsed_ip is not None:
        if require_fqdn:
            raise ValueError("This value is an IP address.")
        return parsed_ip.compressed, True
    if ":" in candidate:
        raise ValueError("The hostname is not valid.")
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The hostname is not valid.") from exc
    if len(ascii_name) > 253:
        raise ValueError("The hostname is not valid.")
    labels = ascii_name.split(".")
    if any(label == "" for label in labels):
        raise ValueError("The hostname is not valid.")
    for label in labels:
        if len(label) > 63 or not _LABEL.fullmatch(label):
            raise ValueError("The hostname is not valid.")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("The hostname is not valid.")
    if len(labels) < 2:
        if require_fqdn:
            raise ValueError("Use a hostname with at least two labels, such as phish.example.")
        if labels[0].isdigit():
            raise ValueError("The hostname is not valid.")
    elif labels[-1].isdigit():
        raise ValueError("The hostname is not valid.")
    return ascii_name, False


def _as_ip(value: str):
    raw = value.strip()
    if raw.startswith("[") and raw.endswith("]") and raw.count("[") == 1 and raw.count("]") == 1:
        raw = raw[1:-1]
    if not raw or "%" in raw or "/" in raw:
        return None
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def _has_junk(value: str) -> bool:
    return any(character.isspace() for character in value) or "\\" in value or "\x00" in value


def detect_media_type(content: bytes) -> str | None:
    for media_type, signature in _SIGNATURES:
        if content.startswith(signature):
            return media_type
    return None


def _evidence(
    contract: Contract,
    *,
    filename: str | None,
    declared_type: str | None,
    content: bytes | None,
    evidence_error: dict | None,
) -> tuple[list, ParsedEvidence | None]:
    if evidence_error is not None:
        return [evidence_error], None
    if content is None:
        return [field_error(("body", "evidence"), "Evidence file is required.", "missing")], None
    if len(content) == 0 and not _basename(filename):
        return [field_error(("body", "evidence"), "Evidence file is required.", "missing")], None

    errors = []
    display_name, ext_type, name_error = _sanitize_filename(filename)
    if name_error:
        errors.append(name_error)
    if len(content) == 0:
        errors.append(field_error(("body", "evidence"), "Evidence file is empty.", "value_error.evidence"))
        return errors, None

    detected = detect_media_type(content)
    if detected is None or detected not in contract.evidence_types:
        errors.append(
            field_error(
                ("body", "evidence"),
                "Evidence must be a JPEG, PNG, or PDF.",
                "value_error.evidence_type",
            )
        )
        detected = None
    elif ext_type is not None and ext_type != detected:
        errors.append(
            field_error(
                ("body", "evidence"),
                "File extension does not match the file contents.",
                "value_error.evidence_type",
            )
        )

    declared = _normalize_declared(declared_type)
    if detected and declared and declared not in {detected, "application/octet-stream"}:
        errors.append(
            field_error(
                ("body", "evidence"),
                "Declared Content-Type does not match the file contents.",
                "value_error.evidence_type",
            )
        )

    if errors or display_name is None or detected is None:
        return errors, None
    return [], ParsedEvidence(display_name, detected, len(content), content)


def _basename(filename: str | None) -> str:
    if not filename:
        return ""
    return Path(filename.replace("\\", "/")).name.strip()


def _sanitize_filename(filename: str | None) -> tuple[str | None, str | None, dict | None]:
    base = _basename(filename)
    if not base or base in {".", ".."}:
        return None, None, field_error(("body", "evidence"), "Evidence filename is required.", "value_error.evidence")
    # pathlib treats ".png" as a stem with no suffix. A leading dot is not a name.
    if base.startswith(".") and base.count(".") == 1:
        suffix = base.lower()
        stem = ""
    else:
        suffix = Path(base).suffix.lower()
        stem = Path(base).stem
    ext_type = _EXTENSIONS.get(suffix)
    if ext_type is None:
        return (
            None,
            None,
            field_error(
                ("body", "evidence"),
                "Evidence filename must end in .jpg, .jpeg, .png, or .pdf.",
                "value_error.evidence_name",
            ),
        )
    if not stem or stem.strip(".") == "":
        return None, None, field_error(("body", "evidence"), "Evidence filename is required.", "value_error.evidence")
    if len(stem) > 200:
        stem = stem[:200]
    return f"{stem}{suffix}", ext_type, None


def _normalize_declared(value: str | None) -> str:
    if not value:
        return ""
    media = value.split(";", 1)[0].strip().lower()
    if media == "image/jpg":
        return "image/jpeg"
    return media
