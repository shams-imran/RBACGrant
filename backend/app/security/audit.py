"""Append-only JSON-lines audit log: stdout plus an optional rotating
file sink (0600, size-based rotation, rotation itself audited)."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .redaction import redact_fields


class AuditLog:
    def __init__(self, file_path: str | None, max_size_bytes: int, keep: int = 10):
        self._lock = threading.Lock()
        self._file_path = Path(file_path) if file_path else None
        self._max_size = max_size_bytes
        self._keep = keep
        self._fh = None
        if self._file_path:
            self._open_file()

    def _open_file(self) -> None:
        assert self._file_path is not None
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._file_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.chmod(self._file_path, 0o600)
        self._fh = os.fdopen(fd, "a", encoding="utf-8")

    def _rotate_if_needed(self) -> None:
        if self._file_path is None or self._fh is None:
            return
        try:
            size = self._file_path.stat().st_size
        except FileNotFoundError:
            return
        if size < self._max_size:
            return
        self._fh.close()
        # shift name.N -> name.N+1, drop the oldest
        for i in range(self._keep - 1, 0, -1):
            src = self._file_path.with_name(self._file_path.name + f".{i}")
            dst = self._file_path.with_name(self._file_path.name + f".{i + 1}")
            if src.exists():
                if i + 1 > self._keep - 1:
                    src.unlink()
                else:
                    src.rename(dst)
        self._file_path.rename(self._file_path.with_name(self._file_path.name + ".1"))
        self._open_file()
        self._write_raw(self._event("audit.rotated", result="ok"))

    def _event(self, action: str, **fields) -> dict:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "action": action,
        }
        event.update(fields)
        return redact_fields(event)

    def _write_raw(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":"), default=str)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        if self._fh is not None:
            self._fh.write(line + "\n")
            self._fh.flush()

    def emit(
        self,
        action: str,
        *,
        user: str | None = None,
        source_ip: str | None = None,
        request_id: str | None = None,
        cluster: str | None = None,
        target: str | None = None,
        result: str = "ok",
        error_class: str | None = None,
        **extra,
    ) -> None:
        """Fields: timestamp, app user, source IP, request ID, cluster,
        action, target, result, error class."""
        event = self._event(
            action,
            user=user,
            source_ip=source_ip,
            request_id=request_id,
            cluster=cluster,
            target=target,
            result=result,
            error_class=error_class,
            **extra,
        )
        event = {k: v for k, v in event.items() if v is not None}
        with self._lock:
            self._rotate_if_needed()
            self._write_raw(event)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None


_audit: AuditLog | None = None


def init_audit(file_path: str | None, max_size_bytes: int) -> AuditLog:
    global _audit
    _audit = AuditLog(file_path, max_size_bytes)
    return _audit


def get_audit() -> AuditLog:
    global _audit
    if _audit is None:
        _audit = AuditLog(None, 64 * 1024 * 1024)
    return _audit
