"""Log redaction: structured logging redacts known secret
field names; a filter scrubs accidental secret-looking values."""
from __future__ import annotations

import logging
import re

REDACTED = "[REDACTED]"

# Field names whose values are always redacted in structured events.
SECRET_FIELD_NAMES = frozenset({
    "password", "password_hash", "admin_password", "token", "vault_token",
    "session_id", "sessionid", "cookie", "authorization", "kubeconfig",
    "client-key-data", "client_key_data", "client-certificate-data", "secret",
    "secret_id", "key", "private_key", "csrf_token", "id_token", "refresh_token",
})

_PATTERNS = [
    re.compile(r"\$argon2[a-z0-9$,=+/.A-Za-z-]+"),          # argon2 hashes
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),  # JWTs
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(client-key-data|client-certificate-data|token)\s*[:=]\s*\S+"),
    re.compile(r"\bhvs\.[A-Za-z0-9_-]{20,}"),               # vault tokens
]


def scrub_text(text: str) -> str:
    for pat in _PATTERNS:
        text = pat.sub(REDACTED, text)
    return text


def redact_fields(data: dict) -> dict:
    """Recursively redact known secret field names in an event dict."""
    out: dict = {}
    for k, v in data.items():
        if k.lower().replace("-", "_") in {n.replace("-", "_") for n in SECRET_FIELD_NAMES}:
            out[k] = REDACTED
        elif isinstance(v, dict):
            out[k] = redact_fields(v)
        elif isinstance(v, str):
            out[k] = scrub_text(v)
        else:
            out[k] = v
    return out


class RedactionFilter(logging.Filter):
    """Attached to every app logger: scrubs secret-looking values from messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            scrubbed = scrub_text(msg)
            if scrubbed != msg:
                record.msg = scrubbed
                record.args = ()
        except Exception:  # noqa: BLE001 — never let redaction break logging
            pass
        return True


def install_redaction() -> None:
    root = logging.getLogger()
    if not any(isinstance(f, RedactionFilter) for f in root.filters):
        root.addFilter(RedactionFilter())
    for handler in root.handlers:
        if not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.addFilter(RedactionFilter())
