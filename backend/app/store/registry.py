"""Cluster registry facade: store backend selection, pre-registered
env clusters, credential cache with TTL."""
from __future__ import annotations

import hashlib
import threading
import time
from datetime import datetime, timezone

from ..models.cluster import ClusterMetadata
from ..secrets.provider import SecretProvider
from ..settings import Settings
from .base import ClusterNotFound, ClusterStore, NoneStore
from .kubeconfig_validation import validate_kubeconfig


class ClusterRegistry:
    def __init__(self, settings: Settings, secret_provider: SecretProvider):
        self.settings = settings
        self._secrets = secret_provider
        self._store = self._make_store(settings, secret_provider)
        self._lock = threading.Lock()
        self._cred_cache: dict[str, tuple[float, str]] = {}
        self._last_used: dict[str, datetime] = {}
        self._env_clusters: dict[str, str] = {}  # name -> secret ref
        if settings.clusters:
            for pair in settings.clusters.split(";"):
                pair = pair.strip()
                if pair:
                    name, _, ref = pair.partition("=")
                    self._env_clusters[name.strip()] = ref.strip()

    @staticmethod
    def _make_store(settings: Settings, secrets_p: SecretProvider) -> ClusterStore:
        if settings.cluster_store == "local":
            from .local_encrypted import LocalEncryptedStore
            return LocalEncryptedStore(settings, secrets_p)
        if settings.cluster_store == "vault":
            from .vault_store import VaultClusterStore
            return VaultClusterStore(settings, secrets_p)
        return NoneStore()

    @property
    def store(self) -> ClusterStore:
        return self._store

    @property
    def backend_name(self) -> str:
        return self.settings.cluster_store

    # -- listing -------------------------------------------------------------
    def list_names(self) -> list[str]:
        return sorted(set(self._store.list_names()) | set(self._env_clusters))

    def is_config_managed(self, name: str) -> bool:
        return name in self._env_clusters

    def get_metadata(self, name: str) -> ClusterMetadata:
        if name in self._env_clusters:
            kubeconfig = self._env_kubeconfig(name)
            validated, _ = validate_kubeconfig(kubeconfig.encode(), self.settings)
            return ClusterMetadata(
                name=name, displayName=name, environment="other",
                serverUrl=validated.server_url, caSha256=validated.ca_sha256,
                credentialType=validated.credential_type,
                storeBackend="config", managedByConfig=True,
                tlsVerified=not validated.insecure_tls,
            )
        return self._store.get_metadata(name)

    def last_used(self, name: str) -> datetime | None:
        return self._last_used.get(name)

    # -- credentials (server-side only,) --------------------------------------
    def _env_kubeconfig(self, name: str) -> str:
        ref = self._env_clusters[name]
        return self._secrets.get(ref).get_secret_value()

    def get_kubeconfig(self, name: str) -> str:
        ttl = self.settings.cluster_cred_cache_ttl_s
        now = time.monotonic()
        with self._lock:
            cached = self._cred_cache.get(name)
            if cached and now - cached[0] < ttl:
                self._last_used[name] = datetime.now(timezone.utc)
                return cached[1]
        if name in self._env_clusters:
            kubeconfig = self._env_kubeconfig(name)
        else:
            kubeconfig = self._store.get_kubeconfig(name)
        with self._lock:
            self._cred_cache[name] = (now, kubeconfig)
            self._last_used[name] = datetime.now(timezone.utc)
        return kubeconfig

    def invalidate_cache(self, name: str | None = None) -> None:
        with self._lock:
            if name is None:
                self._cred_cache.clear()
            else:
                self._cred_cache.pop(name, None)

    # -- writes ----------------------------------------------------------------
    def put(self, name: str, kubeconfig_yaml: str, metadata: ClusterMetadata) -> None:
        if name in self._env_clusters:
            raise PermissionError(f"cluster {name!r} is managed by config")
        self._store.put(name, kubeconfig_yaml, metadata)
        self.invalidate_cache(name)

    def delete(self, name: str) -> None:
        if name in self._env_clusters:
            raise PermissionError(f"cluster {name!r} is managed by config")
        self._store.delete(name)
        self.invalidate_cache(name)

    def rename(self, old: str, new: str) -> None:
        if old in self._env_clusters:
            raise PermissionError(f"cluster {old!r} is managed by config")
        if new in self.list_names():
            raise ValueError(f"cluster {new!r} already exists")
        metadata = self._store.get_metadata(old)
        self._store.rename(old, new, metadata)
        self.invalidate_cache(old)

    def find_duplicate(self, server_url: str, ca_sha256: str, exclude: str | None = None) -> str | None:
        """Same server URL + CA fingerprint under another name."""
        for name in self.list_names():
            if name == exclude:
                continue
            try:
                md = self.get_metadata(name)
            except (ClusterNotFound, Exception):  # noqa: BLE001 — skip unreadable
                continue
            if md.serverUrl == server_url and md.caSha256 == ca_sha256:
                return name
        return None


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_registry: ClusterRegistry | None = None


def get_registry() -> ClusterRegistry:
    if _registry is None:
        raise RuntimeError("ClusterRegistry not initialized")
    return _registry


def set_registry(r: ClusterRegistry | None) -> None:
    global _registry
    _registry = r
