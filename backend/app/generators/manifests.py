"""Turn form models into Kubernetes manifests and YAML."""
from __future__ import annotations

import io

from ruamel.yaml import YAML

from ..models.rbac import BindingSpec, Bundle, RoleSpec, ServiceAccountSpec

_yaml = YAML(typ="safe", pure=True)
_yaml.default_flow_style = False
_yaml.representer.sort_base_mapping_type_on_output = False

RBAC_API = "rbac.authorization.k8s.io/v1"


def _metadata_dict(name: str, namespace: str | None, labels: dict, annotations: dict) -> dict:
    md: dict = {"name": name}
    if namespace:
        md["namespace"] = namespace
    if labels:
        md["labels"] = dict(labels)
    if annotations:
        md["annotations"] = dict(annotations)
    return md


def role_manifest(spec: RoleSpec) -> dict:
    obj: dict = {
        "apiVersion": RBAC_API,
        "kind": spec.kind,
        "metadata": _metadata_dict(
            spec.metadata.name, spec.metadata.namespace,
            spec.metadata.labels, spec.metadata.annotations,
        ),
    }
    if spec.aggregationRule and spec.aggregationRule.clusterRoleSelectors:
        obj["aggregationRule"] = {
            "clusterRoleSelectors": spec.aggregationRule.clusterRoleSelectors
        }
        # Rules of an aggregated ClusterRole are controller-managed.
        obj["rules"] = []
    else:
        obj["rules"] = [_rule_dict(r) for r in spec.rules]
    return obj


def _rule_dict(rule) -> dict:
    d: dict = {}
    if rule.nonResourceURLs:
        d["nonResourceURLs"] = list(rule.nonResourceURLs)
        d["verbs"] = list(rule.verbs)
        return d
    d["apiGroups"] = list(rule.apiGroups) if rule.apiGroups else [""]
    d["resources"] = list(rule.resources)
    d["verbs"] = list(rule.verbs)
    if rule.resourceNames:
        d["resourceNames"] = list(rule.resourceNames)
    return d


def binding_manifests(spec: BindingSpec) -> list[dict]:
    """One manifest per namespace for RoleBindings; one for a CRB."""
    subjects = []
    for s in spec.subjects:
        entry: dict = {"kind": s.kind, "name": s.name}
        if s.api_group:
            entry["apiGroup"] = s.api_group
        if s.kind == "ServiceAccount":
            entry["namespace"] = s.namespace
        subjects.append(entry)
    role_ref = {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": spec.roleRef.kind,
        "name": spec.roleRef.name,
    }
    if spec.kind == "ClusterRoleBinding":
        return [{
            "apiVersion": RBAC_API,
            "kind": "ClusterRoleBinding",
            "metadata": _metadata_dict(spec.name, None, spec.labels, spec.annotations),
            "subjects": subjects,
            "roleRef": role_ref,
        }]
    return [
        {
            "apiVersion": RBAC_API,
            "kind": "RoleBinding",
            "metadata": _metadata_dict(spec.name, ns, spec.labels, spec.annotations),
            "subjects": subjects,
            "roleRef": role_ref,
        }
        for ns in spec.namespaces
    ]


def service_account_manifest(spec: ServiceAccountSpec) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": _metadata_dict(spec.name, spec.namespace, spec.labels, spec.annotations),
        "automountServiceAccountToken": spec.automountServiceAccountToken,
    }


def bundle_manifests(bundle: Bundle) -> list[dict]:
    """ServiceAccounts first so binding subjects exist by the time bindings apply."""
    out: list[dict] = []
    out.extend(service_account_manifest(sa) for sa in bundle.serviceAccounts)
    out.extend(role_manifest(r) for r in bundle.roles)
    for b in bundle.bindings:
        out.extend(binding_manifests(b))
    return out


def to_yaml(manifests: list[dict]) -> str:
    """Multi-document YAML separated by ---."""
    buf = io.StringIO()
    for i, m in enumerate(manifests):
        if i:
            buf.write("---\n")
        _yaml.dump(m, buf)
    return buf.getvalue()


def manifest_filename(manifest: dict) -> str:
    kind = manifest["kind"].lower()
    name = manifest["metadata"]["name"].replace(":", "_")
    ns = manifest["metadata"].get("namespace")
    return f"{kind}-{ns}-{name}.yaml" if ns else f"{kind}-{name}.yaml"
