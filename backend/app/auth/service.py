"""Authentication service: credential resolution, login,
password rotation watch, app roles."""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import threading
import time
from dataclasses import dataclass

from pydantic import SecretStr

from ..secrets.provider import SecretProvider, SecretRefError
from ..settings import Settings, StartupError
from . import passwords
from .sessions import LoginRateLimiter, SessionStore

log = logging.getLogger("rbac_ui.auth")

ROLES = ("viewer", "editor", "admin")

# Capability matrix. Route dependencies reference these permission names.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({
        "builder:use", "lint:run", "export:run",
        "clusters:view", "rbac:view", "cani:run",
    }),
    "editor": frozenset({
        "builder:use", "lint:run", "export:run",
        "clusters:view", "rbac:view", "cani:run",
        "rbac:dry_run", "rbac:apply", "rbac:delete",
        "kubeconfig:generate",
    }),
    "admin": frozenset({
        "builder:use", "lint:run", "export:run",
        "clusters:view", "rbac:view", "cani:run",
        "rbac:dry_run", "rbac:apply", "rbac:delete",
        "kubeconfig:generate",
        "guardrail:override", "clusters:manage", "readonly:toggle", "status:view",
    }),
}


def role_has(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


@dataclass
class UserRecord:
    username: str
    password_hash: str
    role: str
    clusters: list[str] | None  # None = all clusters


class AuthService:
    def __init__(self, settings: Settings, secret_provider: SecretProvider):
        self.settings = settings
        self.secrets = secret_provider
        self.sessions = SessionStore(settings.session_idle_timeout_s, settings.session_max_age_s)
        self.limiter = LoginRateLimiter(settings.login_max_attempts, settings.login_lockout_s)
        self._lock = threading.Lock()
        self._admin_hash: str | None = None
        self._users: dict[str, UserRecord] = {}
        self._watch_thread: threading.Thread | None = None
        self._stop = threading.Event()
        if settings.auth_mode == "local":
            self._load_credentials(initial=True)

    # -- credential loading ---------------------------------------------------
    def _resolve_admin_secret(self) -> SecretStr:
        s = self.settings
        if s.admin_password_ref:
            return self.secrets.get(s.admin_password_ref, use_cache=False)
        if s.admin_password_hash:
            return SecretStr(s.admin_password_hash)
        if s.admin_password:
            return SecretStr(s.admin_password)
        raise StartupError("no admin password configured")

    def _to_hash(self, value: SecretStr, *, initial: bool) -> str:
        raw = value.get_secret_value()
        if passwords.looks_like_argon2_hash(raw):
            return raw
        # Plaintext accepted: check policy, hash in memory, warn.
        if initial:
            passwords.check_policy(raw)
            log.warning(
                "admin password was provided as plaintext; it has been hashed in "
                "memory — prefer an Argon2id hash"
            )
        return passwords.hash_password(raw)

    def _load_credentials(self, *, initial: bool) -> None:
        value = self._resolve_admin_secret()
        with self._lock:
            self._admin_hash = self._to_hash(value, initial=initial)
        # Drop plaintext from the environment.
        if self.settings.admin_password:
            os.environ.pop("RBAC_UI_ADMIN_PASSWORD", None)
            self.settings.admin_password = None
        if self.settings.users_ref:
            self._load_users(initial=initial)

    def _load_users(self, *, initial: bool) -> None:
        """{username: {password_hash, role, clusters}}."""
        raw = self.secrets.get(self.settings.users_ref, use_cache=False).get_secret_value()
        data = json.loads(raw)
        users: dict[str, UserRecord] = {}
        for name, entry in data.items():
            role = entry.get("role", "viewer")
            if role not in ROLES:
                raise StartupError(f"user {name!r} has unknown role {role!r}")
            users[name] = UserRecord(
                username=name,
                password_hash=entry["password_hash"],
                role=role,
                clusters=entry.get("clusters"),
            )
        with self._lock:
            self._users = users

    # -- login ----------------------------------------------------------------
    def authenticate(self, username: str, password: str) -> UserRecord | None:
        """Returns the matched user or None. Always burns hash work so timing
        does not reveal whether the username exists."""
        with self._lock:
            admin_hash = self._admin_hash
            user = self._users.get(username)
        if username == self.settings.admin_username and admin_hash:
            if passwords.verify_password(admin_hash, password):
                return UserRecord(username, admin_hash, "admin", None)
            return None
        if user is not None:
            if passwords.verify_password(user.password_hash, password):
                return user
            return None
        passwords.verify_dummy(password)
        return None

    def verify_current_password(self, username: str, password: str) -> bool:
        """Step-up re-authentication."""
        return self.authenticate(username, password) is not None

    def user_can_see_cluster(self, clusters: list[str] | None, name: str) -> bool:
        """Per-user cluster allowlist with globs; None means all."""
        if clusters is None:
            return True
        return any(fnmatch.fnmatch(name, pat) for pat in clusters)

    # -- rotation watch -------------------------------------------------------
    def start_rotation_watch(self, interval_s: int = 60) -> None:
        if self.settings.auth_mode != "local" or not self.settings.admin_password_ref:
            return
        if self._watch_thread is not None:
            return
        self._watch_thread = threading.Thread(
            target=self._watch_loop, args=(interval_s,), daemon=True, name="password-rotation"
        )
        self._watch_thread.start()

    def stop_rotation_watch(self) -> None:
        self._stop.set()

    def _watch_loop(self, interval_s: int) -> None:
        while not self._stop.wait(interval_s):
            try:
                self.check_rotation_once()
            except Exception:  # noqa: BLE001
                log.warning("password rotation check crashed; keeping last known hash")

    def check_rotation_once(self) -> bool:
        """Re-read the password source. Only a successfully-read CHANGED value
        revokes sessions; a fetch error never revokes anything."""
        try:
            value = self._resolve_admin_secret()
        except SecretRefError:
            log.warning("secret backend fetch failed; keeping last known password hash")
            return False
        raw = value.get_secret_value()
        with self._lock:
            old = self._admin_hash
        if passwords.looks_like_argon2_hash(raw):
            changed = raw != old
            new_hash = raw
        else:
            changed = old is None or not passwords.verify_password(old, raw)
            new_hash = passwords.hash_password(raw) if changed else old
        if changed:
            with self._lock:
                self._admin_hash = new_hash
            n = self.sessions.revoke_user(self.settings.admin_username)
            log.info("admin password changed at source; revoked %d session(s)", n)
            return True
        return False


_auth: AuthService | None = None


def get_auth_service() -> AuthService:
    if _auth is None:
        raise RuntimeError("AuthService not initialized")
    return _auth


def set_auth_service(service: AuthService | None) -> None:
    global _auth
    _auth = service
