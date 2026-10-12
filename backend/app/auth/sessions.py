"""Server-side session store and brute-force protection.

Process-local by design: the server refuses to start with multiple workers
(settings.validate_startup) because split counters weaken lockout.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field


@dataclass
class Session:
    session_id: str
    username: str
    role: str
    created_at: float
    last_seen: float
    last_step_up: float = 0.0
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    clusters: list[str] | None = None  # None = all (single-admin mode)


class SessionStore:
    """Holds 256-bit random session IDs. IDs never appear in URLs or logs."""

    def __init__(self, idle_timeout_s: int, max_age_s: int):
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self.idle_timeout_s = idle_timeout_s
        self.max_age_s = max_age_s

    def create(self, username: str, role: str, clusters: list[str] | None = None) -> Session:
        sid = secrets.token_urlsafe(32)  # 256 bits
        now = time.time()
        session = Session(sid, username, role, now, now, last_step_up=now, clusters=clusters)
        with self._lock:
            self._sessions[sid] = session
        return session

    def get(self, session_id: str) -> Session | None:
        now = time.time()
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return None
            if now - s.last_seen > self.idle_timeout_s or now - s.created_at > self.max_age_s:
                del self._sessions[session_id]
                return None
            s.last_seen = now
            return s

    def invalidate(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def revoke_user(self, username: str) -> int:
        """Password rotation: revoke one user's sessions."""
        with self._lock:
            doomed = [sid for sid, s in self._sessions.items() if s.username == username]
            for sid in doomed:
                del self._sessions[sid]
        return len(doomed)

    def revoke_all(self) -> int:
        with self._lock:
            n = len(self._sessions)
            self._sessions.clear()
        return n

    def mark_step_up(self, session_id: str) -> None:
        with self._lock:
            s = self._sessions.get(session_id)
            if s:
                s.last_step_up = time.time()

    def has_fresh_step_up(self, session: Session, window_s: int) -> bool:
        return time.time() - session.last_step_up <= window_s


class LoginRateLimiter:
    """Escalating delays per username and per IP; hard lock is per-IP
    only, so an attacker can't deny the admin account with garbage passwords."""

    def __init__(self, max_attempts: int, lockout_s: int):
        self._lock = threading.Lock()
        self.max_attempts = max_attempts
        self.lockout_s = lockout_s
        self._by_user: dict[str, int] = {}
        self._by_ip: dict[str, int] = {}
        self._ip_locked_until: dict[str, float] = {}

    def check(self, username: str, ip: str) -> tuple[bool, float]:
        """Returns (allowed, delay_seconds). allowed=False means the IP is locked."""
        now = time.time()
        with self._lock:
            locked_until = self._ip_locked_until.get(ip, 0)
            if locked_until > now:
                return False, locked_until - now
            failures = max(self._by_user.get(username, 0), self._by_ip.get(ip, 0))
        if failures >= self.max_attempts:
            # exponential delay past the threshold: 1s, 2s, 4s ... capped at 30s
            return True, min(2 ** (failures - self.max_attempts), 30)
        return True, 0.0

    def record_failure(self, username: str, ip: str) -> None:
        with self._lock:
            self._by_user[username] = self._by_user.get(username, 0) + 1
            self._by_ip[ip] = self._by_ip.get(ip, 0) + 1
            if self._by_ip[ip] >= self.max_attempts:
                self._ip_locked_until[ip] = time.time() + self.lockout_s

    def record_success(self, username: str, ip: str) -> None:
        with self._lock:
            self._by_user.pop(username, None)
            self._by_ip.pop(ip, None)
            self._ip_locked_until.pop(ip, None)

    def is_ip_locked(self, ip: str) -> bool:
        with self._lock:
            return self._ip_locked_until.get(ip, 0) > time.time()
