"""Pydantic models for the RBAC builder forms and validation
rules."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

DNS1123_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
DNS1123_SUBDOMAIN = re.compile(
    r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$"
)
# RBAC object names also allow path-ish system names like "system:node-proxier".
RBAC_NAME = re.compile(r"^[a-zA-Z0-9:_.\-]{1,253}$")

VALID_VERBS = {
    "get", "list", "watch", "create", "update", "patch", "delete", "deletecollection",
    "use", "bind", "escalate", "impersonate", "approve", "sign", "*",
}


def validate_dns1123_label(name: str, what: str = "name") -> str:
    if not DNS1123_LABEL.match(name):
        raise ValueError(
            f"{what} {name!r} must be a DNS-1123 label: lowercase alphanumerics "
            "and '-', 1-63 chars, starting and ending with an alphanumeric"
        )
    return name


class PolicyRule(BaseModel):
    apiGroups: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    verbs: list[str] = Field(min_length=1)
    resourceNames: list[str] = Field(default_factory=list)
    nonResourceURLs: list[str] = Field(default_factory=list)

    @field_validator("verbs")
    @classmethod
    def _verbs_known(cls, v: list[str]) -> list[str]:
        unknown = set(v) - VALID_VERBS
        if unknown:
            raise ValueError(f"unknown verbs: {sorted(unknown)}")
        return v

    @model_validator(mode="after")
    def _resource_xor_nonresource(self) -> "PolicyRule":
        if self.nonResourceURLs:
            if self.apiGroups or self.resources or self.resourceNames:
                raise ValueError(
                    "a rule with nonResourceURLs must not set apiGroups, "
                    "resources or resourceNames"
                )
            for url in self.nonResourceURLs:
                if not url.startswith("/"):
                    raise ValueError(f"nonResourceURL {url!r} must start with '/'")
        elif not self.resources:
            raise ValueError("a rule needs resources (or nonResourceURLs in a ClusterRole)")
        return self


class Metadata(BaseModel):
    name: str
    namespace: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not RBAC_NAME.match(v):
            raise ValueError(f"invalid object name {v!r}")
        return v

    @field_validator("namespace")
    @classmethod
    def _ns(cls, v: str | None) -> str | None:
        if v is not None:
            validate_dns1123_label(v, "namespace")
        return v


class AggregationRule(BaseModel):
    clusterRoleSelectors: list[dict] = Field(default_factory=list)


class RoleSpec(BaseModel):
    """Form state for a Role or ClusterRole."""
    kind: Literal["Role", "ClusterRole"]
    metadata: Metadata
    rules: list[PolicyRule] = Field(default_factory=list)
    aggregationRule: AggregationRule | None = None

    @model_validator(mode="after")
    def _rules(self) -> "RoleSpec":
        if self.kind == "Role":
            if not self.metadata.namespace:
                raise ValueError("a Role needs a namespace")
            for rule in self.rules:
                if rule.nonResourceURLs:
                    raise ValueError("nonResourceURLs are allowed only in a ClusterRole")
            if self.aggregationRule:
                raise ValueError("aggregationRule is only valid on a ClusterRole")
        else:
            if self.metadata.namespace:
                raise ValueError("a ClusterRole must not set a namespace")
        return self


class Subject(BaseModel):
    kind: Literal["User", "Group", "ServiceAccount"]
    name: str
    namespace: str | None = None

    @model_validator(mode="after")
    def _sa_namespace(self) -> "Subject":
        if self.kind == "ServiceAccount":
            if not self.namespace:
                raise ValueError("a ServiceAccount subject needs a namespace")
            validate_dns1123_label(self.name, "ServiceAccount name")
        return self

    @property
    def api_group(self) -> str | None:
        # The tool fills in the right apiGroup per kind.
        return None if self.kind == "ServiceAccount" else "rbac.authorization.k8s.io"


class RoleRef(BaseModel):
    kind: Literal["Role", "ClusterRole"]
    name: str


class BindingSpec(BaseModel):
    """Form state for a binding. namespaces holds one entry for a plain RoleBinding
    and N entries for multi-namespace binding."""
    kind: Literal["RoleBinding", "ClusterRoleBinding"]
    name: str
    namespaces: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    roleRef: RoleRef
    subjects: list[Subject] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not RBAC_NAME.match(v):
            raise ValueError(f"invalid binding name {v!r}")
        return v

    @model_validator(mode="after")
    def _scope(self) -> "BindingSpec":
        if self.kind == "RoleBinding":
            if not self.namespaces:
                raise ValueError("a RoleBinding needs at least one namespace")
            for ns in self.namespaces:
                validate_dns1123_label(ns, "namespace")
        else:
            if self.namespaces:
                raise ValueError("a ClusterRoleBinding is cluster-scoped; drop the namespaces")
            if self.roleRef.kind == "Role":
                raise ValueError(
                    "a ClusterRoleBinding can only reference a ClusterRole"
                )
        return self


class ServiceAccountSpec(BaseModel):
    """SA created in the same bundle."""
    name: str
    namespace: str
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    automountServiceAccountToken: bool = False

    @field_validator("name", "namespace")
    @classmethod
    def _dns(cls, v: str) -> str:
        return validate_dns1123_label(v)


class Bundle(BaseModel):
    """Everything the builders produce, previewed and exported together."""
    roles: list[RoleSpec] = Field(default_factory=list)
    bindings: list[BindingSpec] = Field(default_factory=list)
    serviceAccounts: list[ServiceAccountSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> "Bundle":
        # Names unique inside the bundle (per kind+namespace).
        seen: set[tuple] = set()
        for r in self.roles:
            key = ("role", r.kind, r.metadata.namespace, r.metadata.name)
            if key in seen:
                raise ValueError(f"duplicate {r.kind} {r.metadata.name!r} in bundle")
            seen.add(key)
        for b in self.bindings:
            for ns in b.namespaces or [None]:
                key = ("binding", b.kind, ns, b.name)
                if key in seen:
                    raise ValueError(f"duplicate {b.kind} {b.name!r} in bundle")
                seen.add(key)
        for sa in self.serviceAccounts:
            key = ("sa", sa.namespace, sa.name)
            if key in seen:
                raise ValueError(f"duplicate ServiceAccount {sa.name!r} in bundle")
            seen.add(key)
        return self
