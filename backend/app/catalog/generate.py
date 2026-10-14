"""Build-time offline catalog generation.

The catalog (API groups, resources, subresources, verbs per supported minor)
is generated, never hand-maintained. Two sources:

  python -m app.catalog.generate --from-cluster   # live discovery via kubeconfig
  python -m app.catalog.generate --builtin        # regenerate from the baseline

The baseline below encodes upstream discovery data for the core and named
groups as shipped in Kubernetes 1.24–1.31; per-minor deltas are applied on
top. Output: app/catalog/data/catalog-<minor>.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"

SUPPORTED_MINORS = ["1.24", "1.25", "1.26", "1.27", "1.28", "1.29", "1.30", "1.31"]

RW = ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
RO = ["get", "list", "watch"]

# group -> resource -> verbs  (baseline: stable APIs present since 1.24)
BASELINE: dict[str, dict[str, list[str]]] = {
    "": {
        "pods": RW, "pods/log": ["get"], "pods/exec": ["create", "get"],
        "pods/attach": ["create", "get"], "pods/portforward": ["create", "get"],
        "pods/ephemeralcontainers": ["get", "patch", "update"],
        "pods/status": ["get", "patch", "update"], "pods/eviction": ["create"],
        "services": RW, "services/status": ["get", "patch", "update"],
        "endpoints": RW, "configmaps": RW, "secrets": RW,
        "serviceaccounts": RW, "serviceaccounts/token": ["create"],
        "namespaces": ["create", "delete", "get", "list", "patch", "update", "watch"],
        "namespaces/status": ["get", "patch", "update"],
        "nodes": RW, "nodes/status": ["get", "patch", "update"], "nodes/proxy": RW,
        "persistentvolumes": RW, "persistentvolumeclaims": RW,
        "events": RW, "limitranges": RW, "resourcequotas": RW,
        "replicationcontrollers": RW, "replicationcontrollers/scale": ["get", "patch", "update"],
        "podtemplates": RW, "bindings": ["create"],
    },
    "apps": {
        "deployments": RW, "deployments/scale": ["get", "patch", "update"],
        "deployments/status": ["get", "patch", "update"],
        "replicasets": RW, "replicasets/scale": ["get", "patch", "update"],
        "statefulsets": RW, "statefulsets/scale": ["get", "patch", "update"],
        "daemonsets": RW, "controllerrevisions": RW,
    },
    "batch": {"jobs": RW, "jobs/status": ["get", "patch", "update"], "cronjobs": RW},
    "networking.k8s.io": {
        "ingresses": RW, "ingresses/status": ["get", "patch", "update"],
        "ingressclasses": RW, "networkpolicies": RW,
    },
    "rbac.authorization.k8s.io": {
        "roles": RW + ["bind", "escalate"],
        "clusterroles": RW + ["bind", "escalate"],
        "rolebindings": RW, "clusterrolebindings": RW,
    },
    "storage.k8s.io": {
        "storageclasses": RW, "volumeattachments": RW,
        "csidrivers": RW, "csinodes": RW, "csistoragecapacities": RW,
    },
    "autoscaling": {"horizontalpodautoscalers": RW},
    "policy": {"poddisruptionbudgets": RW},
    "apiextensions.k8s.io": {"customresourcedefinitions": RW},
    "admissionregistration.k8s.io": {
        "validatingwebhookconfigurations": RW, "mutatingwebhookconfigurations": RW,
    },
    "certificates.k8s.io": {
        "certificatesigningrequests": RW,
        "certificatesigningrequests/approval": ["get", "patch", "update"],
        "certificatesigningrequests/status": ["get", "patch", "update"],
        "signers": ["approve", "sign"],
    },
    "authentication.k8s.io": {"tokenreviews": ["create"]},
    "authorization.k8s.io": {
        "subjectaccessreviews": ["create"], "selfsubjectaccessreviews": ["create"],
        "selfsubjectrulesreviews": ["create"], "localsubjectaccessreviews": ["create"],
    },
    "coordination.k8s.io": {"leases": RW},
    "discovery.k8s.io": {"endpointslices": RW},
    "events.k8s.io": {"events": RW},
    "node.k8s.io": {"runtimeclasses": RW},
    "scheduling.k8s.io": {"priorityclasses": RW},
    "flowcontrol.apiserver.k8s.io": {"flowschemas": RW, "prioritylevelconfigurations": RW},
    "apiregistration.k8s.io": {"apiservices": RW},
}

# minor -> additions {group: {resource: verbs}} / removals {group: [resource]}
DELTAS: dict[str, dict] = {
    "1.25": {"remove": {"policy": ["podsecuritypolicies"]}},
    "1.26": {"add": {"admissionregistration.k8s.io": {
        "validatingadmissionpolicies": RW, "validatingadmissionpolicybindings": RW}}},
    "1.28": {"add": {"authentication.k8s.io": {"selfsubjectreviews": ["create"]}}},
    "1.29": {"add": {"flowcontrol.apiserver.k8s.io": {}}},
    "1.30": {"add": {"": {}}},
    "1.31": {"add": {"coordination.k8s.io": {}}},
}

VERBS = ["get", "list", "watch", "create", "update", "patch", "delete",
         "deletecollection", "use", "bind", "escalate", "impersonate", "approve", "sign"]


def build_catalog(minor: str) -> dict:
    groups: dict[str, dict[str, list[str]]] = {
        g: dict(res) for g, res in BASELINE.items()
    }
    # 1.24 still had PSP; it is removed in 1.25+.
    if minor == "1.24":
        groups.setdefault("policy", {})["podsecuritypolicies"] = RW + ["use"]
    for m in SUPPORTED_MINORS:
        if m > minor:
            break
        delta = DELTAS.get(m, {})
        for g, res in delta.get("add", {}).items():
            groups.setdefault(g, {}).update(res)
        for g, removed in delta.get("remove", {}).items():
            for r in removed:
                groups.get(g, {}).pop(r, None)
    return {
        "minor": minor,
        "verbs": VERBS,
        "groups": [
            {
                "name": g,
                "displayName": "core" if g == "" else g,
                "resources": [
                    {"name": r, "verbs": v} for r, v in sorted(res.items())
                ],
            }
            for g, res in sorted(groups.items())
        ],
    }


def generate_builtin() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    for minor in SUPPORTED_MINORS:
        out = DATA_DIR / f"catalog-{minor}.json"
        out.write_text(json.dumps(build_catalog(minor), indent=1))
        print(f"wrote {out}")
    (DATA_DIR / "index.json").write_text(json.dumps({"minors": SUPPORTED_MINORS}))


def generate_from_cluster() -> None:
    """Regenerate the newest minor's catalog from live discovery."""
    from kubernetes import client, config

    config.load_kube_config()
    api = client.ApiClient()
    groups: dict[str, dict[str, list[str]]] = {}

    def raw(path: str):
        # Shares the client-version shim used by the runtime code paths.
        from ..k8s.operations import _raw_call
        from ..settings import get_settings
        return _raw_call(api, get_settings(), path)

    def collect(path: str, group_name: str) -> None:
        data = raw(path)
        for r in data.get("resources", []):
            groups.setdefault(group_name, {})[r["name"]] = r.get("verbs", [])

    collect("/api/v1", "")
    group_list = raw("/apis")
    for g in group_list.get("groups", []):
        collect(f"/apis/{g['preferredVersion']['groupVersion']}", g["name"])

    version = raw("/version")
    minor = f"{version['major']}.{version['minor'].rstrip('+')}"
    catalog = {
        "minor": minor, "verbs": VERBS,
        "groups": [
            {"name": g, "displayName": "core" if g == "" else g,
             "resources": [{"name": r, "verbs": v} for r, v in sorted(res.items())]}
            for g, res in sorted(groups.items())
        ],
    }
    DATA_DIR.mkdir(exist_ok=True)
    out = DATA_DIR / f"catalog-{minor}.json"
    out.write_text(json.dumps(catalog, indent=1))
    print(f"wrote {out} from live discovery")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--builtin", action="store_true")
    mode.add_argument("--from-cluster", action="store_true")
    args = parser.parse_args()
    if args.builtin:
        generate_builtin()
    else:
        generate_from_cluster()


if __name__ == "__main__":
    main()
