"""Cluster registry metadata. Never contains credential material."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .rbac import validate_dns1123_label

Environment = Literal["prod", "staging", "dev", "other"]


class ClusterMetadata(BaseModel):
    name: str
    displayName: str = ""
    environment: Environment = "other"
    description: str = ""
    serverUrl: str
    publicApiUrl: str | None = None  # override for generated kubeconfigs
    caSha256: str
    identity: str = ""
    identityGroups: list[str] = Field(default_factory=list)
    credentialType: str = ""       # "client-cert" | "token" | "exec"
    credentialExpiry: datetime | None = None
    addedBy: str = ""
    addedAt: datetime | None = None
    updatedBy: str = ""
    updatedAt: datetime | None = None
    storeBackend: str = ""
    managedByConfig: bool = False  # pre-registered, read-only
    tlsVerified: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return validate_dns1123_label(v, "cluster name")


class ClusterSummary(BaseModel):
    """What list endpoints return — metadata only, never credentials."""
    metadata: ClusterMetadata
    lastUsed: datetime | None = None
    connectionStatus: str = "unknown"
