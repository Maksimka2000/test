"""Validation error objects shaped like the OpenAPI FieldError schema."""

from __future__ import annotations


def field_error(loc: tuple, message: str, error_type: str) -> dict:
    return {"loc": list(loc), "msg": message, "type": error_type}
