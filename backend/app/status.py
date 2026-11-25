"""Target lifecycle values. These must match TargetStatusValue in openapi.yaml."""

PENDING = "pending"
RUNNING = "running"
AWAITING_CAPTCHA = "awaiting_captcha"
RETRYING = "retrying"
SUBMITTED = "submitted"
FAILED = "failed"
SKIPPED = "skipped"
STATUSES = (PENDING, RUNNING, AWAITING_CAPTCHA, RETRYING, SUBMITTED, FAILED, SKIPPED)
# A restart returns these to pending and keeps the attempt count.
INTERRUPTED = (RUNNING, AWAITING_CAPTCHA, RETRYING, "queued")
ACTIVE = (PENDING, RUNNING, AWAITING_CAPTCHA, RETRYING)
