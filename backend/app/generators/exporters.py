"""Export formats: combined YAML, zip, kubectl commands, kustomize."""
from __future__ import annotations

import io
import shlex
import zipfile

from ..models.rbac import Bundle
from .manifests import bundle_manifests, manifest_filename, to_yaml


def export_yaml(bundle: Bundle) -> str:
    return to_yaml(bundle_manifests(bundle))


def export_zip(bundle: Bundle) -> bytes:
    manifests = bundle_manifests(bundle)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for m in manifests:
            zf.writestr(manifest_filename(m), to_yaml([m]))
        zf.writestr("kustomization.yaml", export_kustomization(bundle))
    return buf.getvalue()


def export_kustomization(bundle: Bundle) -> str:
    files = [manifest_filename(m) for m in bundle_manifests(bundle)]
    lines = ["apiVersion: kustomize.config.k8s.io/v1beta1", "kind: Kustomization", "resources:"]
    lines += [f"  - {f}" for f in files]
    return "\n".join(lines) + "\n"


def export_kubectl(bundle: Bundle) -> str:
    """Equivalent imperative kubectl commands. Rules that kubectl create cannot
    express (multiple rules, resourceNames on some verbs) fall back to apply."""
    cmds: list[str] = []
    for sa in bundle.serviceAccounts:
        cmds.append(f"kubectl create serviceaccount {shlex.quote(sa.name)} -n {shlex.quote(sa.namespace)}")
    for role in bundle.roles:
        if role.aggregationRule or len(role.rules) != 1 or role.rules[0].nonResourceURLs:
            cmds.append(f"# {role.kind} {role.metadata.name}: too complex for kubectl create; use kubectl apply -f")
            continue
        rule = role.rules[0]
        parts = ["kubectl create", "role" if role.kind == "Role" else "clusterrole",
                 shlex.quote(role.metadata.name)]
        parts.append("--verb=" + ",".join(rule.verbs))
        resources = []
        for res in rule.resources:
            groups = [g for g in rule.apiGroups if g] or [""]
            g = groups[0]
            resources.append(f"{res}.{g}" if g else res)
        parts.append("--resource=" + ",".join(resources))
        for rn in rule.resourceNames:
            parts.append(f"--resource-name={shlex.quote(rn)}")
        if role.kind == "Role":
            parts.append(f"-n {shlex.quote(role.metadata.namespace)}")
        cmds.append(" ".join(parts))
    for b in bundle.bindings:
        base = ["kubectl create",
                "rolebinding" if b.kind == "RoleBinding" else "clusterrolebinding",
                shlex.quote(b.name)]
        ref_flag = "--role" if b.roleRef.kind == "Role" else "--clusterrole"
        base.append(f"{ref_flag}={shlex.quote(b.roleRef.name)}")
        for s in b.subjects:
            if s.kind == "User":
                base.append(f"--user={shlex.quote(s.name)}")
            elif s.kind == "Group":
                base.append(f"--group={shlex.quote(s.name)}")
            else:
                base.append(f"--serviceaccount={shlex.quote(s.namespace)}:{shlex.quote(s.name)}")
        if b.kind == "RoleBinding":
            for ns in b.namespaces:
                cmds.append(" ".join(base + [f"-n {shlex.quote(ns)}"]))
        else:
            cmds.append(" ".join(base))
    return "\n".join(cmds) + "\n"
