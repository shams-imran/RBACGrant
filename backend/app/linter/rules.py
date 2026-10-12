"""Risk linter, based on the Kubernetes RBAC good-practices doc.
Works on generated manifests, so the same rules run against the builder bundle
and against live cluster RBAC."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel

from ..models.rbac import Bundle
from ..generators.manifests import bundle_manifests


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    message: str
    object_kind: str
    object_name: str
    object_namespace: str | None = None
    suggestion: str | None = None


SECRET_READ_VERBS = {"get", "list", "watch", "*"}
WRITE_VERBS = {"create", "update", "patch", "*"}
EXEC_LIKE = {"pods/exec", "pods/attach", "pods/portforward", "pods/ephemeralcontainers"}
WORKLOAD_RESOURCES = {
    "pods", "deployments", "replicasets", "statefulsets", "daemonsets",
    "jobs", "cronjobs", "replicationcontrollers",
}
WEBHOOK_RESOURCES = {
    "validatingwebhookconfigurations", "mutatingwebhookconfigurations",
    "validatingadmissionpolicies", "validatingadmissionpolicybindings",
    "customresourcedefinitions",
}
DANGEROUS_SUBJECTS_CRITICAL = {"system:masters", "system:unauthenticated", "system:anonymous"}


def _rule_matches(rule: dict, resource: str, verbs: set[str]) -> bool:
    r_resources = set(rule.get("resources", []))
    r_verbs = set(rule.get("verbs", []))
    res_hit = resource in r_resources or "*" in r_resources
    verb_hit = bool(verbs & r_verbs) or "*" in r_verbs
    return res_hit and verb_hit


def _obj_ref(m: dict) -> dict:
    return {
        "object_kind": m.get("kind", ""),
        "object_name": m.get("metadata", {}).get("name", ""),
        "object_namespace": m.get("metadata", {}).get("namespace"),
    }


def _lint_role(m: dict) -> list[Finding]:
    out: list[Finding] = []
    ref = _obj_ref(m)
    kind = m.get("kind")
    rules = m.get("rules") or []

    for rule in rules:
        groups = set(rule.get("apiGroups", []))
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        names = rule.get("resourceNames", [])

        if "*" in verbs and "*" in resources:
            out.append(Finding(rule_id="RL-C3", severity=Severity.critical,
                message="wildcard '*' verbs on '*' resources grants everything in scope",
                suggestion="list only the resources and verbs the subject needs", **ref))
        else:
            for what, values in (("verbs", verbs), ("resources", resources), ("apiGroups", groups)):
                if "*" in values:
                    out.append(Finding(rule_id="RL-H1", severity=Severity.high,
                        message=f"wildcard '*' in {what}",
                        suggestion=f"replace '*' with the explicit {what} you need", **ref))

        if _rule_matches(rule, "secrets", SECRET_READ_VERBS):
            out.append(Finding(rule_id="RL-H2", severity=Severity.high,
                message="read access to secrets (list and watch reveal secret contents)",
                suggestion="narrow with resourceNames, or avoid granting secrets at all", **ref))
        if _rule_matches(rule, "secrets", WRITE_VERBS):
            out.append(Finding(rule_id="RL-H3", severity=Severity.high,
                message="write access to secrets lets a subject mint a legacy "
                        "service-account-token Secret and impersonate any SA in the namespace",
                suggestion="avoid write access to secrets; use narrower resources", **ref))

        for v in ("escalate", "bind"):
            if v in verbs:
                out.append(Finding(rule_id="RL-H4", severity=Severity.high,
                    message=f"'{v}' on RBAC objects allows privilege escalation",
                    suggestion="restrict with resourceNames to an approved role list", **ref))
        if "impersonate" in verbs:
            out.append(Finding(rule_id="RL-H5", severity=Severity.high,
                message="'impersonate' allows acting as other users, groups or serviceaccounts", **ref))
        if _rule_matches(rule, "serviceaccounts/token", {"create", "*"}):
            out.append(Finding(rule_id="RL-H6", severity=Severity.high,
                message="'create' on serviceaccounts/token mints tokens for any SA in scope", **ref))
        if _rule_matches(rule, "certificatesigningrequests/approval", WRITE_VERBS) or (
            "approve" in verbs and "signers" in resources
        ):
            out.append(Finding(rule_id="RL-H7", severity=Severity.high,
                message="CSR approval rights can issue client certificates for arbitrary users", **ref))
        if _rule_matches(rule, "nodes/proxy", SECRET_READ_VERBS | WRITE_VERBS):
            out.append(Finding(rule_id="RL-H8", severity=Severity.high,
                message="nodes/proxy gives kubelet API access, bypassing API-server audit and RBAC", **ref))
        if _rule_matches(rule, "persistentvolumes", {"create", "*"}):
            out.append(Finding(rule_id="RL-H9", severity=Severity.high,
                message="'create' on persistentvolumes allows hostPath volumes (host filesystem access)", **ref))
        for wr in WEBHOOK_RESOURCES:
            if _rule_matches(rule, wr, WRITE_VERBS | {"delete"}):
                out.append(Finding(rule_id="RL-H10", severity=Severity.high,
                    message=f"write access to {wr} can intercept or reconfigure the cluster control plane", **ref))
        for er in EXEC_LIKE:
            if _rule_matches(rule, er, {"create", "get", "*"}):
                out.append(Finding(rule_id="RL-H11", severity=Severity.high,
                    message=f"{er} allows code execution in / traffic to workload containers", **ref))

        workload_hits = resources & WORKLOAD_RESOURCES if "*" not in resources else set()
        if workload_hits and verbs & {"create", "*"}:
            out.append(Finding(rule_id="RL-M1", severity=Severity.medium,
                message=f"'create' on workloads ({', '.join(sorted(workload_hits))}) gives "
                        "implicit access to secrets and serviceaccounts they can mount", **ref))
        if _rule_matches(rule, "namespaces", {"update", "patch"}):
            out.append(Finding(rule_id="RL-M2", severity=Severity.medium,
                message="namespace update/patch can change Pod Security labels (policy bypass)", **ref))
        if _rule_matches(rule, "nodes", {"patch"}):
            out.append(Finding(rule_id="RL-M3", severity=Severity.medium,
                message="'patch' on nodes can alter node labels and steer scheduling", **ref))
        for ep in ("endpoints", "endpointslices"):
            if _rule_matches(rule, ep, {"create", "*"}):
                out.append(Finding(rule_id="RL-M4", severity=Severity.medium,
                    message=f"'create' on {ep} can redirect in-cluster traffic", **ref))
        if "deletecollection" in verbs:
            out.append(Finding(rule_id="RL-M5", severity=Severity.medium,
                message="'deletecollection' deletes whole sets of objects at once", **ref))

        if not names and len(resources) == 1 and not resources & {"*"} and verbs <= {"get"}:
            out.append(Finding(rule_id="RL-L1", severity=Severity.low,
                message="single-resource 'get' rule without resourceNames",
                suggestion="add resourceNames if a specific object is meant", **ref))

    if kind == "ClusterRole":
        labels = m.get("metadata", {}).get("labels", {}) or {}
        if any(k.startswith("rbac.authorization.k8s.io/aggregate-to-") for k in labels):
            out.append(Finding(rule_id="RL-H12", severity=Severity.high,
                message="aggregate-to-* label silently widens the built-in view/edit/admin roles cluster-wide",
                **ref))

    annotations = m.get("metadata", {}).get("annotations", {}) or {}
    if not _has_traceability(annotations):
        out.append(Finding(rule_id="RL-I1", severity=Severity.info,
            message="missing owner/description annotations",
            suggestion="set rbac-builder/owner and rbac-builder/description for traceability", **ref))
    return out


# "ticket" is the pre-rename spelling still present on older objects.
_TRACE_ANNOTATIONS = ("rbac-builder/owner", "rbac-builder/description", "rbac-builder/ticket")


def _has_traceability(annotations: dict) -> bool:
    return any(a in annotations for a in _TRACE_ANNOTATIONS)


def _lint_binding(m: dict, roles_by_key: dict[tuple, dict]) -> list[Finding]:
    out: list[Finding] = []
    ref = _obj_ref(m)
    kind = m.get("kind")
    role_ref = m.get("roleRef", {}) or {}
    subjects = m.get("subjects", []) or []

    if role_ref.get("name") == "cluster-admin":
        out.append(Finding(rule_id="RL-C1", severity=Severity.critical,
            message="binds the cluster-admin ClusterRole",
            suggestion="grant a narrower role; cluster-admin is full control", **ref))

    for s in subjects:
        name = s.get("name", "")
        if name in DANGEROUS_SUBJECTS_CRITICAL:
            out.append(Finding(rule_id="RL-C2", severity=Severity.critical,
                message=f"binds dangerous subject {name!r}", **ref))
        if s.get("kind") == "Group" and name == "system:authenticated":
            out.append(Finding(rule_id="RL-H13", severity=Severity.high,
                message="binds to system:authenticated (every authenticated identity)", **ref))
        if s.get("kind") == "ServiceAccount" and name == "default":
            out.append(Finding(rule_id="RL-M6", severity=Severity.medium,
                message="binds the 'default' ServiceAccount, which every pod uses unless told otherwise",
                suggestion="create a dedicated ServiceAccount", **ref))

    # Secrets read via a ClusterRoleBinding is critical (cluster-wide reach).
    if kind == "ClusterRoleBinding":
        target = roles_by_key.get(("ClusterRole", None, role_ref.get("name")))
        if target:
            for rule in target.get("rules") or []:
                if _rule_matches(rule, "secrets", SECRET_READ_VERBS):
                    out.append(Finding(rule_id="RL-C4", severity=Severity.critical,
                        message="grants secrets read cluster-wide (ClusterRoleBinding to a role with secrets access)",
                        **ref))
                    break
        namespaced_only = True
        if target:
            for rule in target.get("rules") or []:
                if rule.get("nonResourceURLs"):
                    namespaced_only = False
                res = set(rule.get("resources", []))
                if res & {"nodes", "namespaces", "persistentvolumes", "clusterroles",
                          "clusterrolebindings", "customresourcedefinitions", "*"}:
                    namespaced_only = False
            if namespaced_only and target.get("rules"):
                out.append(Finding(rule_id="RL-M7", severity=Severity.medium,
                    message="ClusterRoleBinding used where the granted resources are namespaced; "
                            "a RoleBinding per namespace would be narrower", **ref))

    # Dangling refs inside the bundle (low: the role may exist on the cluster).
    key = (role_ref.get("kind"), m.get("metadata", {}).get("namespace") if role_ref.get("kind") == "Role" else None,
           role_ref.get("name"))
    builtin = role_ref.get("name") in {"view", "edit", "admin", "cluster-admin"}
    if roles_by_key and key not in roles_by_key and not builtin:
        out.append(Finding(rule_id="RL-L2", severity=Severity.low,
            message=f"roleRef {role_ref.get('name')!r} is not in this bundle (dangling unless it exists on the cluster)",
            **ref))

    annotations = m.get("metadata", {}).get("annotations", {}) or {}
    expires = annotations.get("rbac-builder/expires-at")
    if expires:
        try:
            when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if when < datetime.now(timezone.utc):
                out.append(Finding(rule_id="RL-L3", severity=Severity.low,
                    message=f"grant expired at {expires} (rbac-builder/expires-at)", **ref))
        except ValueError:
            pass
    if not _has_traceability(annotations):
        out.append(Finding(rule_id="RL-I1", severity=Severity.info,
            message="missing owner/description annotations",
            suggestion="set rbac-builder/owner and rbac-builder/description for traceability", **ref))
    return out


def _lint_service_account(m: dict) -> list[Finding]:
    out: list[Finding] = []
    if m.get("automountServiceAccountToken") is True:
        out.append(Finding(rule_id="RL-M8", severity=Severity.medium,
            message="automountServiceAccountToken: true mounts the token into every pod using this SA",
            suggestion="keep automount off and project the token only where needed",
            **_obj_ref(m)))
    return out


def lint_manifests(manifests: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    roles_by_key: dict[tuple, dict] = {}
    for m in manifests:
        if m.get("kind") in ("Role", "ClusterRole"):
            md = m.get("metadata", {})
            roles_by_key[(m["kind"], md.get("namespace"), md.get("name"))] = m
    for m in manifests:
        kind = m.get("kind")
        if kind in ("Role", "ClusterRole"):
            findings.extend(_lint_role(m))
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            findings.extend(_lint_binding(m, roles_by_key))
        elif kind == "ServiceAccount":
            findings.extend(_lint_service_account(m))
    order = {s: i for i, s in enumerate(Severity)}
    findings.sort(key=lambda f: order[f.severity])
    return findings


def lint_bundle(bundle: Bundle) -> list[Finding]:
    return lint_manifests(bundle_manifests(bundle))


def least_privilege_score(findings: list[Finding]) -> int:
    """100 minus weighted findings, floored at 0."""
    weights = {Severity.critical: 40, Severity.high: 15, Severity.medium: 5,
               Severity.low: 2, Severity.info: 0}
    return max(0, 100 - sum(weights[f.severity] for f in findings))
