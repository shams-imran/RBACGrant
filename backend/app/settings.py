"""Application settings. All configuration comes from environment variables,
optionally via a .env file. Secret values may be secret refs."""
from __future__ import annotations

import ipaddress
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DURATION_RE = re.compile(r"^(\d+)\s*(s|m|h|d)?$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, None: 1}

_SIZE_RE = re.compile(r"^(\d+)\s*(B|KiB|MiB|GiB)?$", re.IGNORECASE)
_SIZE_UNITS = {"b": 1, "kib": 1024, "mib": 1024**2, "gib": 1024**3, None: 1}


def parse_duration(value: str | int | float) -> int:
    """Parse '15m', '8h', '7d', '90s' or bare seconds into seconds."""
    if isinstance(value, (int, float)):
        return int(value)
    m = _DURATION_RE.match(value.strip())
    if not m:
        raise ValueError(f"invalid duration: {value!r}")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def parse_size(value: str | int) -> int:
    if isinstance(value, int):
        return value
    m = _SIZE_RE.match(value.strip())
    if not m:
        raise ValueError(f"invalid size: {value!r}")
    unit = m.group(2).lower() if m.group(2) else None
    return int(m.group(1)) * _SIZE_UNITS[unit]


def _default_runtime_dir() -> str:
    # Linux: tmpfs. macOS has no /dev/shm: 0700 dir under $TMPDIR.
    if sys.platform == "linux" and os.path.isdir("/dev/shm"):
        return "/dev/shm/k8s-rbac-builder"
    return str(Path(tempfile.gettempdir()) / "k8s-rbac-builder-runtime")


def _default_data_dir() -> str:
    if os.path.isdir("/data") and os.environ.get("RBAC_UI_IN_CONTAINER"):
        return "/data"
    return str(Path.home() / ".local" / "share" / "k8s-rbac-builder")


# The server is usually started from backend/ (see Makefile), so resolve the
# repo-root .env explicitly; a .env in the current directory still wins.
_REPO_ROOT_ENV = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RBAC_UI_", env_file=(str(_REPO_ROOT_ENV), ".env"),
        env_file_encoding="utf-8", extra="ignore"
    )

    # --- 5.1 server and web ---
    bind_addr: str = "127.0.0.1"
    port: int = 8080
    public_url: str = "http://127.0.0.1:8080"
    allowed_hosts: str = "localhost,127.0.0.1"
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    trusted_proxies: str | None = None
    allow_insecure_http: bool = False
    read_only: bool = False
    log_level: str = "info"
    audit_log_file: str | None = None
    audit_log_max_size: str = "64MiB"
    profiles_dir: str = "./profiles"
    brand_name: str = "RBACGrant"
    brand_logo_file: str | None = None

    # --- 5.2 authentication ---
    auth_mode: Literal["local", "none", "oidc"] = "local"
    admin_username: str = "admin"
    admin_password_ref: str | None = None
    admin_password_hash: str | None = None
    admin_password: str | None = None
    users_ref: str | None = None
    session_idle_timeout: str = "15m"
    session_max_age: str = "8h"
    step_up_window: str = "5m"
    login_max_attempts: int = 5
    login_lockout: str = "15m"
    min_password_length: int = 6

    # --- 5.3 vault, store, credentials ---
    vault_auth_method: Literal["token", "approle", "kubernetes"] = "token"
    vault_token_file: str | None = None
    vault_role_id: str | None = None
    vault_secret_id_file: str | None = None
    vault_k8s_role: str | None = None
    vault_kv_mount: str = "secret"
    vault_path_prefix: str = "k8s-rbac-builder"
    cluster_store: Literal["vault", "local", "none"] = "none"
    data_dir: str = _default_data_dir()
    store_key_ref: str | None = None
    clusters: str | None = None  # pre-registered: "name=ref;name=ref"
    runtime_dir: str = _default_runtime_dir()
    cluster_cred_cache_ttl: str = "5m"
    secret_cache_ttl: str = "60s"
    allowed_api_servers: str | None = None
    allow_insecure_cluster_tls: bool = False
    allowed_exec_plugins: str | None = None
    default_token_ttl: str = "8h"
    max_token_ttl: str = "7d"
    default_cert_ttl: str = "24h"
    max_cert_ttl: str = "7d"
    allow_legacy_sa_tokens: bool = False
    allow_loopback_api_servers: bool = False
    k8s_timeout: str = "15s"
    policy_file: str | None = None

    # internal/testing
    workers: int = 1
    session_store: Literal["memory"] = "memory"

    # --- computed helpers ---
    @property
    def allowed_hosts_list(self) -> list[str]:
        return [h.strip().lower() for h in self.allowed_hosts.split(",") if h.strip()]

    @property
    def session_idle_timeout_s(self) -> int:
        return parse_duration(self.session_idle_timeout)

    @property
    def session_max_age_s(self) -> int:
        return parse_duration(self.session_max_age)

    @property
    def step_up_window_s(self) -> int:
        return parse_duration(self.step_up_window)

    @property
    def login_lockout_s(self) -> int:
        return parse_duration(self.login_lockout)

    @property
    def secret_cache_ttl_s(self) -> int:
        return parse_duration(self.secret_cache_ttl)

    @property
    def cluster_cred_cache_ttl_s(self) -> int:
        return parse_duration(self.cluster_cred_cache_ttl)

    @property
    def default_token_ttl_s(self) -> int:
        return parse_duration(self.default_token_ttl)

    @property
    def max_token_ttl_s(self) -> int:
        return parse_duration(self.max_token_ttl)

    @property
    def default_cert_ttl_s(self) -> int:
        return parse_duration(self.default_cert_ttl)

    @property
    def max_cert_ttl_s(self) -> int:
        return parse_duration(self.max_cert_ttl)

    @property
    def k8s_timeout_s(self) -> int:
        return parse_duration(self.k8s_timeout)

    @property
    def audit_log_max_size_bytes(self) -> int:
        return parse_size(self.audit_log_max_size)

    @property
    def public_url_https(self) -> bool:
        return urlparse(self.public_url).scheme == "https"

    @field_validator("port")
    @classmethod
    def _port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port out of range")
        return v


class StartupError(RuntimeError):
    """Configuration refused; the server must not start."""


def _is_loopback_host(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_startup(settings: Settings) -> list[str]:
    """Enforce the startup invariants.
    Returns warnings; raises StartupError on refusal."""
    warnings: list[str] = []

    # Auth off is allowed only offline + loopback.
    if settings.auth_mode == "none":
        if settings.cluster_store != "none":
            raise StartupError(
                "RBAC_UI_AUTH_MODE=none requires RBAC_UI_CLUSTER_STORE=none: "
                "a cluster store holds admin credentials and demands login"
            )
        if not _is_loopback_host(settings.bind_addr):
            raise StartupError(
                "RBAC_UI_AUTH_MODE=none is allowed only on a loopback bind address"
            )
    elif settings.auth_mode == "oidc":
        raise StartupError("RBAC_UI_AUTH_MODE=oidc is not implemented yet")
    else:
        # local auth: a password source must exist — there is no default password.
        if not (
            settings.admin_password_ref
            or settings.admin_password_hash
            or settings.admin_password
        ):
            raise StartupError(
                "no admin password configured: set RBAC_UI_ADMIN_PASSWORD_REF, "
                "RBAC_UI_ADMIN_PASSWORD_HASH or RBAC_UI_ADMIN_PASSWORD. "
                "There is no default password."
            )

    # Sessions/lockout are process-local; refuse multiple workers.
    if settings.workers > 1:
        raise StartupError(
            "multiple workers with the in-memory session store split sessions and "
            "lockout counters; run a single process"
        )

    # Off-loopback plain HTTP refused without the explicit flag.
    pub = urlparse(settings.public_url)
    if pub.scheme != "https" and not _is_loopback_host(pub.hostname or ""):
        if not settings.allow_insecure_http:
            raise StartupError(
                "RBAC_UI_PUBLIC_URL is plain http on a non-loopback host; set TLS or "
                "RBAC_UI_ALLOW_INSECURE_HTTP=true behind a trusted TLS proxy"
            )
        warnings.append("serving plain HTTP off-loopback behind a TLS proxy")
    if not _is_loopback_host(settings.bind_addr) and pub.scheme != "https" and not settings.allow_insecure_http:
        raise StartupError(
            "binding off-loopback without HTTPS requires RBAC_UI_ALLOW_INSECURE_HTTP=true"
        )

    # Local store needs a key, and never from inside the data dir.
    if settings.cluster_store == "local":
        if not settings.store_key_ref:
            raise StartupError(
                "RBAC_UI_CLUSTER_STORE=local requires RBAC_UI_STORE_KEY_REF"
            )
        ref = settings.store_key_ref
        if ref.startswith("file:"):
            key_path = Path(ref[len("file:"):]).resolve()
            data_dir = Path(settings.data_dir).expanduser().resolve()
            if data_dir in key_path.parents or key_path == data_dir:
                raise StartupError(
                    "the store key file must not live inside RBAC_UI_DATA_DIR"
                )

    # 5: a .env file must not be group/world readable.
    env_file = Path(".env")
    if env_file.exists():
        mode = stat.S_IMODE(env_file.stat().st_mode)
        if mode & 0o077:
            warnings.append(f".env is mode {oct(mode)}; it should be 0600")

    if settings.admin_password:
        warnings.append(
            "RBAC_UI_ADMIN_PASSWORD is plaintext in the environment; it is hashed in "
            "memory and dropped from os.environ, but prefer a hash or a secret ref"
        )

    return warnings


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def set_settings(s: Settings) -> None:
    """Test hook / explicit initialization."""
    global _settings
    _settings = s
