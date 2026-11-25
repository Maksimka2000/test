"""Load the OpenAPI document and the limits the server enforces."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml


class ContractError(RuntimeError):
    pass


def spec_path() -> Path:
    app_dir = Path(__file__).resolve().parent
    candidates = (
        app_dir.parent.parent / "openapi.yaml",  # source checkout: repo root
        app_dir.parent / "openapi.yaml",  # image layout: /app/openapi.yaml
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ContractError("openapi.yaml was not found next to the application.")


@dataclass(frozen=True)
class Contract:
    spec: dict
    submission_types: tuple
    threat_types: tuple
    statuses: tuple
    evidence_types: tuple
    max_batch_size: int
    max_evidence_bytes: int
    max_url_length: int
    max_reason_length: int
    max_targets_chars: int


@lru_cache(maxsize=1)
def load_contract() -> Contract:
    path = spec_path()
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(spec, dict):
        raise ContractError(f"{path} did not contain an OpenAPI document.")
    limits = spec["info"]["x-limits"]
    schemas = spec["components"]["schemas"]
    return Contract(
        spec=spec,
        submission_types=tuple(schemas["SubmissionType"]["enum"]),
        threat_types=tuple(schemas["ThreatType"]["enum"]),
        statuses=tuple(schemas["TargetStatusValue"]["enum"]),
        evidence_types=tuple(limits["allowedEvidenceTypes"]),
        max_batch_size=int(limits["maxBatchSize"]),
        max_evidence_bytes=int(limits["maxEvidenceBytes"]),
        max_url_length=int(limits["maxUrlLength"]),
        max_reason_length=int(schemas["Reason"]["maxLength"]),
        max_targets_chars=int(schemas["TargetsText"]["maxLength"]),
    )
