"""Golden-file style generator tests."""
from app.generators.exporters import export_kubectl, export_kustomization
from app.generators.manifests import bundle_manifests, to_yaml
from app.models.rbac import Bundle

DEV_BUNDLE = {
    "roles": [{
        "kind": "Role",
        "metadata": {"name": "pod-reader", "namespace": "team-a"},
        "rules": [{"apiGroups": [""], "resources": ["pods", "pods/log"],
                   "verbs": ["get", "list", "watch"]}],
    }],
    "bindings": [{
        "kind": "RoleBinding", "name": "pod-readers", "namespaces": ["team-a"],
        "roleRef": {"kind": "Role", "name": "pod-reader"},
        "subjects": [{"kind": "ServiceAccount", "name": "reader", "namespace": "team-a"}],
    }],
    "serviceAccounts": [{"name": "reader", "namespace": "team-a"}],
}

EXPECTED_YAML = """\
apiVersion: v1
kind: ServiceAccount
metadata:
  name: reader
  namespace: team-a
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: team-a
rules:
- apiGroups:
  - ''
  resources:
  - pods
  - pods/log
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-readers
  namespace: team-a
subjects:
- kind: ServiceAccount
  name: reader
  namespace: team-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
"""


def test_golden_yaml():
    bundle = Bundle.model_validate(DEV_BUNDLE)
    assert to_yaml(bundle_manifests(bundle)) == EXPECTED_YAML


def test_subject_api_groups():
    bundle = Bundle.model_validate({
        "bindings": [{
            "kind": "ClusterRoleBinding", "name": "b", "namespaces": [],
            "roleRef": {"kind": "ClusterRole", "name": "view"},
            "subjects": [
                {"kind": "User", "name": "alice"},
                {"kind": "Group", "name": "devs"},
                {"kind": "ServiceAccount", "name": "sa1", "namespace": "ns1"},
            ],
        }],
    })
    [m] = bundle_manifests(bundle)
    subs = m["subjects"]
    assert subs[0]["apiGroup"] == "rbac.authorization.k8s.io"
    assert subs[1]["apiGroup"] == "rbac.authorization.k8s.io"
    assert "apiGroup" not in subs[2] and subs[2]["namespace"] == "ns1"


def test_multi_namespace_binding_fr26():
    bundle = Bundle.model_validate({
        "bindings": [{
            "kind": "RoleBinding", "name": "b", "namespaces": ["ns1", "ns2", "ns3"],
            "roleRef": {"kind": "ClusterRole", "name": "edit"},
            "subjects": [{"kind": "Group", "name": "devs"}],
        }],
    })
    manifests = bundle_manifests(bundle)
    assert [m["metadata"]["namespace"] for m in manifests] == ["ns1", "ns2", "ns3"]


def test_kubectl_export():
    bundle = Bundle.model_validate(DEV_BUNDLE)
    out = export_kubectl(bundle)
    assert "kubectl create serviceaccount reader -n team-a" in out
    assert "kubectl create role pod-reader --verb=get,list,watch" in out
    assert "--serviceaccount=team-a:reader" in out


def test_kustomize_export():
    bundle = Bundle.model_validate(DEV_BUNDLE)
    out = export_kustomization(bundle)
    assert "kind: Kustomization" in out
    assert "role-team-a-pod-reader.yaml" in out


def test_validation_rejects_bad_input():
    import pytest
    from pydantic import ValidationError
    # SA subject without namespace
    with pytest.raises(ValidationError):
        Bundle.model_validate({
            "bindings": [{"kind": "RoleBinding", "name": "b", "namespaces": ["ns"],
                          "roleRef": {"kind": "Role", "name": "r"},
                          "subjects": [{"kind": "ServiceAccount", "name": "x"}]}],
        })
    # nonResourceURLs in a Role
    with pytest.raises(ValidationError):
        Bundle.model_validate({
            "roles": [{"kind": "Role", "metadata": {"name": "r", "namespace": "ns"},
                       "rules": [{"nonResourceURLs": ["/metrics"], "verbs": ["get"]}]}],
        })
    # CRB -> Role roleRef
    with pytest.raises(ValidationError):
        Bundle.model_validate({
            "bindings": [{"kind": "ClusterRoleBinding", "name": "b", "namespaces": [],
                          "roleRef": {"kind": "Role", "name": "r"},
                          "subjects": [{"kind": "User", "name": "u"}]}],
        })
    # duplicate names in the bundle
    role = {"kind": "ClusterRole", "metadata": {"name": "dup"},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}
    with pytest.raises(ValidationError):
        Bundle.model_validate({"roles": [role, role]})
