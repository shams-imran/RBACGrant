"""Builder API + profiles + generated-credential invariants."""
from tests.conftest import login

BUNDLE = {
    "roles": [{"kind": "Role", "metadata": {"name": "r", "namespace": "ns"},
               "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}],
    "bindings": [], "serviceAccounts": [],
}


def test_preview_and_lint(client):
    login(client)
    r = client.post("/api/preview", json=BUNDLE)
    assert r.status_code == 200
    data = r.json()
    assert "kind: Role" in data["yaml"]
    assert data["score"] <= 100


def test_export_formats(client):
    login(client)
    assert client.post("/api/export/yaml", json=BUNDLE).status_code == 200
    assert client.post("/api/export/zip", json=BUNDLE).status_code == 200
    assert client.post("/api/export/kubectl", json=BUNDLE).status_code == 200
    assert client.post("/api/export/kustomize", json=BUNDLE).status_code == 200
    assert client.post("/api/export/nope", json=BUNDLE).status_code == 404


def test_catalog(client):
    login(client)
    minors = client.get("/api/catalog").json()["minors"]
    assert "1.31" in minors
    cat = client.get("/api/catalog/1.31").json()
    names = {g["name"] for g in cat["groups"]}
    assert "" in names and "rbac.authorization.k8s.io" in names
    core = next(g for g in cat["groups"] if g["name"] == "")
    assert any(r["name"] == "pods/exec" for r in core["resources"])


def test_profile_roundtrip(client):
    login(client)
    body = {"name": "dev", "bundle": BUNDLE, "variables": {"team": "core"}}
    assert client.put("/api/profiles/dev", json=body).status_code == 200
    got = client.get("/api/profiles/dev").json()
    assert got["version"] == 1 and got["bundle"]["roles"][0]["metadata"]["name"] == "r"
    assert client.delete("/api/profiles/dev").status_code == 200


def test_profile_rejects_credentials(client):
    """Profiles never contain credentials."""
    login(client)
    bad = {
        "name": "leaky",
        "bundle": {
            "roles": [{"kind": "Role",
                       "metadata": {"name": "r", "namespace": "ns",
                                    "annotations": {"note": "-----BEGIN PRIVATE KEY-----"}},
                       "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}],
            "bindings": [], "serviceAccounts": [],
        },
        "variables": {},
    }
    assert client.put("/api/profiles/leaky", json=bad).status_code == 422


def test_templates(client):
    login(client)
    templates = client.get("/api/templates").json()["templates"]
    ids = {t["id"] for t in templates}
    assert {"developer", "readonly-auditor", "ci-deployer", "monitoring",
            "namespace-admin", "operator-full", "operator-restricted"} <= ids
    full = client.get("/api/templates/operator-full").json()
    assert "cluster-admin" in full["description"]


def test_import_yaml(client):
    login(client)
    yaml_text = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: imported
  namespace: ns
  resourceVersion: "12345"
  uid: abc
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
"""
    r = client.post("/api/import-yaml", content=yaml_text.encode(),
                    headers={"Content-Type": "application/yaml"})
    assert r.status_code == 200
    [obj] = r.json()["objects"]
    assert obj["metadata"]["name"] == "imported"
    # server-managed fields dropped
    assert "resourceVersion" not in obj["metadata"] and "uid" not in obj["metadata"]


def test_guardrails_endpoint(client):
    login(client)
    bad = {
        "roles": [], "serviceAccounts": [],
        "bindings": [{"kind": "ClusterRoleBinding", "name": "b", "namespaces": [],
                      "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                      "subjects": [{"kind": "Group", "name": "everyone"}]}],
    }
    d = client.post("/api/guardrails", json=bad).json()
    assert d["override_required"] and not d["allowed"]


def test_read_only_toggle_admin_only(client):
    login(client)
    r = client.post("/api/read-only", json={"readOnly": True})
    assert r.status_code == 200 and r.json()["readOnly"] is True
    client.post("/api/read-only", json={"readOnly": False})
