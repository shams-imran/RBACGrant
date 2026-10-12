"""Vault-backed cluster store: one KV v2 secret per cluster with
max_versions=2; delete destroys all versions and metadata."""
from __future__ import annotations

import json

from ..models.cluster import ClusterMetadata
from ..secrets.provider import SecretProvider
from ..settings import Settings
from .base import ClusterNotFound, ClusterStore, ClusterStoreError


class VaultClusterStore(ClusterStore):
    def __init__(self, settings: Settings, secret_provider: SecretProvider):
        self.settings = settings
        self._secrets = secret_provider
        self._mount = settings.vault_kv_mount
        self._prefix = settings.vault_path_prefix

    def _client(self):
        return self._secrets._vault()  # shares auth/renewal with the secret fetcher

    def _path(self, name: str) -> str:
        return f"{self._prefix}/clusters/{name}"

    def list_names(self) -> list[str]:
        import hvac
        try:
            resp = self._client().secrets.kv.v2.list_secrets(
                path=f"{self._prefix}/clusters", mount_point=self._mount
            )
            return sorted(resp["data"]["keys"])
        except hvac.exceptions.InvalidPath:
            return []

    def _read(self, name: str) -> dict:
        import hvac
        try:
            resp = self._client().secrets.kv.v2.read_secret_version(
                path=self._path(name), mount_point=self._mount,
                raise_on_deleted_version=True,
            )
        except hvac.exceptions.InvalidPath as exc:
            raise ClusterNotFound(name) from exc
        return resp["data"]["data"]

    def get_metadata(self, name: str) -> ClusterMetadata:
        data = self._read(name)
        return ClusterMetadata.model_validate(json.loads(data["metadata"]))

    def get_kubeconfig(self, name: str) -> str:
        return self._read(name)["kubeconfig"]

    def put(self, name: str, kubeconfig_yaml: str, metadata: ClusterMetadata) -> None:
        client = self._client()
        path = self._path(name)
        client.secrets.kv.v2.create_or_update_secret(
            path=path, mount_point=self._mount,
            secret={"kubeconfig": kubeconfig_yaml, "metadata": metadata.model_dump_json()},
        )
        try:
            client.secrets.kv.v2.update_metadata(
                path=path, mount_point=self._mount, max_versions=2
            )
        except Exception as exc:  # noqa: BLE001
            raise ClusterStoreError(f"failed to set max_versions on {name!r}") from exc

    def delete(self, name: str) -> None:
        import hvac
        client = self._client()
        path = self._path(name)
        try:
            meta = client.secrets.kv.v2.read_secret_metadata(path=path, mount_point=self._mount)
        except hvac.exceptions.InvalidPath as exc:
            raise ClusterNotFound(name) from exc
        versions = [int(v) for v in meta["data"]["versions"]]
        if versions:
            client.secrets.kv.v2.destroy_secret_versions(
                path=path, mount_point=self._mount, versions=versions
            )
        client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=path, mount_point=self._mount
        )
