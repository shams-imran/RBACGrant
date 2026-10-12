"""ClusterStore interface. Credentials go in; only metadata comes out
of list operations. Nothing ever returns a stored kubeconfig to the UI."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models.cluster import ClusterMetadata


class ClusterStoreError(RuntimeError):
    pass


class ClusterNotFound(ClusterStoreError):
    pass


class ClusterStore(ABC):
    @abstractmethod
    def list_names(self) -> list[str]: ...

    @abstractmethod
    def get_metadata(self, name: str) -> ClusterMetadata: ...

    @abstractmethod
    def get_kubeconfig(self, name: str) -> str:
        """Server-side use only; never exposed by any API route."""

    @abstractmethod
    def put(self, name: str, kubeconfig_yaml: str, metadata: ClusterMetadata) -> None: ...

    @abstractmethod
    def delete(self, name: str) -> None:
        """Destroys all stored versions."""

    def rename(self, old: str, new: str, metadata: ClusterMetadata) -> None:
        """Write new, then destroy old."""
        kubeconfig = self.get_kubeconfig(old)
        # Re-point the normalized config's names at the new cluster name.
        kubeconfig = kubeconfig.replace(f"name: {old}", f"name: {new}").replace(
            f"cluster: {old}", f"cluster: {new}").replace(f"user: {old}", f"user: {new}").replace(
            f"current-context: {old}", f"current-context: {new}")
        metadata = metadata.model_copy(update={"name": new})
        self.put(new, kubeconfig, metadata)
        self.delete(old)


class NoneStore(ClusterStore):
    """RBAC_UI_CLUSTER_STORE=none: pure offline mode."""

    def list_names(self) -> list[str]:
        return []

    def get_metadata(self, name: str) -> ClusterMetadata:
        raise ClusterNotFound(name)

    def get_kubeconfig(self, name: str) -> str:
        raise ClusterNotFound(name)

    def put(self, name: str, kubeconfig_yaml: str, metadata: ClusterMetadata) -> None:
        raise ClusterStoreError("no cluster store is configured (RBAC_UI_CLUSTER_STORE=none)")

    def delete(self, name: str) -> None:
        raise ClusterNotFound(name)
