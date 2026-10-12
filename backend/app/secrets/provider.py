"""Secret fetcher: one interface over env / file / vault / sops refs.

Refs:
    env:NAME
    file:/abs/path            (trailing newline trimmed; must be 0600)
    vault:<kv-mount>/<path>#<field>
    sops:/abs/path#<field>
Resolved values are pydantic SecretStr and cached for RBAC_UI_SECRET_CACHE_TTL.
Error messages name the ref, never the value.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from pathlib import Path

from pydantic import SecretStr

from ..settings import Settings, get_settings


class SecretRefError(RuntimeError):
    """A ref failed to resolve. The message must never contain a secret value."""


def _check_file_perms(path: Path, ref: str) -> None:
    st = path.stat()
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise SecretRefError(
            f"secret file for ref {ref!r} is group- or world-readable "
            f"(mode {oct(mode)}); chmod it to 0600"
        )


class SecretProvider:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._cache: dict[str, tuple[float, SecretStr]] = {}
        self._vault_client = None

    # -- public API ---------------------------------------------------------
    def get(self, ref: str, *, use_cache: bool = True) -> SecretStr:
        ttl = self._settings.secret_cache_ttl_s
        if use_cache and ref in self._cache:
            at, value = self._cache[ref]
            if time.monotonic() - at < ttl:
                return value
        value = self._resolve(ref)
        self._cache[ref] = (time.monotonic(), value)
        return value

    def invalidate(self, ref: str | None = None) -> None:
        if ref is None:
            self._cache.clear()
        else:
            self._cache.pop(ref, None)

    def check(self, ref: str) -> None:
        """Startup self-check: resolve or fail fast naming the ref."""
        self.get(ref, use_cache=False)

    # -- resolvers ----------------------------------------------------------
    def _resolve(self, ref: str) -> SecretStr:
        scheme, _, rest = ref.partition(":")
        try:
            if scheme == "env":
                return self._from_env(rest, ref)
            if scheme == "file":
                return self._from_file(rest, ref)
            if scheme == "vault":
                return self._from_vault(rest, ref)
            if scheme == "sops":
                return self._from_sops(rest, ref)
            if scheme in ("aws-sm", "gcp-sm", "az-kv", "vault-transit"):
                raise SecretRefError(
                    f"secret ref scheme {scheme!r} is not implemented yet (P2)"
                )
        except SecretRefError:
            raise
        except Exception as exc:  # noqa: BLE001 — wrap without leaking values
            raise SecretRefError(
                f"failed to resolve secret ref {ref!r}: {exc.__class__.__name__}"
            ) from exc
        raise SecretRefError(f"unknown secret ref scheme in {ref!r}")

    def _from_env(self, name: str, ref: str) -> SecretStr:
        value = os.environ.get(name)
        if value is None:
            raise SecretRefError(f"environment variable for ref {ref!r} is not set")
        return SecretStr(value)

    def _from_file(self, path_str: str, ref: str) -> SecretStr:
        path = Path(path_str)
        if not path.is_absolute():
            raise SecretRefError(f"file ref {ref!r} must use an absolute path")
        if not path.is_file():
            raise SecretRefError(f"secret file for ref {ref!r} does not exist")
        _check_file_perms(path, ref)
        return SecretStr(path.read_text(encoding="utf-8").rstrip("\n"))

    def _from_vault(self, rest: str, ref: str) -> SecretStr:
        path_part, sep, field = rest.partition("#")
        if not sep or not field:
            raise SecretRefError(f"vault ref {ref!r} needs a #field suffix")
        mount, _, secret_path = path_part.partition("/")
        if not mount or not secret_path:
            raise SecretRefError(f"vault ref {ref!r} must be vault:<mount>/<path>#<field>")
        client = self._vault()
        resp = client.secrets.kv.v2.read_secret_version(
            path=secret_path, mount_point=mount, raise_on_deleted_version=True
        )
        data = resp["data"]["data"]
        if field not in data:
            raise SecretRefError(f"field for ref {ref!r} not present in the Vault secret")
        return SecretStr(str(data[field]))

    def _from_sops(self, rest: str, ref: str) -> SecretStr:
        path_str, sep, field = rest.partition("#")
        if not sep or not field:
            raise SecretRefError(f"sops ref {ref!r} needs a #field suffix")
        path = Path(path_str)
        if not path.is_absolute() or not path.is_file():
            raise SecretRefError(f"sops file for ref {ref!r} does not exist or is not absolute")
        try:
            out = subprocess.run(
                ["sops", "--decrypt", "--output-type", "json", str(path)],
                capture_output=True, check=True, timeout=15,
            )
        except FileNotFoundError as exc:
            raise SecretRefError(
                f"'sops' binary not found on PATH for ref {ref!r}"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise SecretRefError(
                f"sops decryption failed for ref {ref!r} (exit {exc.returncode})"
            ) from exc
        data = json.loads(out.stdout)
        if field not in data:
            raise SecretRefError(f"field for ref {ref!r} not present in the SOPS file")
        return SecretStr(str(data[field]))

    # -- vault client ---------------------------------------------------------
    def _vault(self):
        if self._vault_client is not None and self._vault_client.is_authenticated():
            return self._vault_client
        if os.environ.get("VAULT_SKIP_VERIFY"):
            raise SecretRefError("VAULT_SKIP_VERIFY is refused: TLS verification is mandatory")
        import hvac

        addr = os.environ.get("VAULT_ADDR")
        if not addr:
            raise SecretRefError("VAULT_ADDR is not set")
        kwargs: dict = {"url": addr, "verify": os.environ.get("VAULT_CACERT", True)}
        namespace = os.environ.get("VAULT_NAMESPACE")
        if namespace:
            kwargs["namespace"] = namespace
        client = hvac.Client(**kwargs)

        s = self._settings
        method = s.vault_auth_method
        if method == "token":
            token = None
            if s.vault_token_file:
                token_path = Path(s.vault_token_file)
                _check_file_perms(token_path, "RBAC_UI_VAULT_TOKEN_FILE")
                token = token_path.read_text().strip()
            else:
                token = os.environ.get("VAULT_TOKEN")
            if not token:
                raise SecretRefError("no Vault token: set VAULT_TOKEN or RBAC_UI_VAULT_TOKEN_FILE")
            client.token = token
        elif method == "approle":
            if not (s.vault_role_id and s.vault_secret_id_file):
                raise SecretRefError(
                    "approle auth needs RBAC_UI_VAULT_ROLE_ID and RBAC_UI_VAULT_SECRET_ID_FILE"
                )
            sid_path = Path(s.vault_secret_id_file)
            _check_file_perms(sid_path, "RBAC_UI_VAULT_SECRET_ID_FILE")
            client.auth.approle.login(
                role_id=s.vault_role_id, secret_id=sid_path.read_text().strip()
            )
        elif method == "kubernetes":
            if not s.vault_k8s_role:
                raise SecretRefError("kubernetes auth needs RBAC_UI_VAULT_K8S_ROLE")
            jwt = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text()
            client.auth.kubernetes.login(role=s.vault_k8s_role, jwt=jwt)
        if not client.is_authenticated():
            raise SecretRefError("Vault authentication failed")
        self._vault_client = client
        return client


_provider: SecretProvider | None = None


def get_secret_provider() -> SecretProvider:
    global _provider
    if _provider is None:
        _provider = SecretProvider(get_settings())
    return _provider


def set_secret_provider(p: SecretProvider | None) -> None:
    global _provider
    _provider = p
