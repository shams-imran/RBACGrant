"""Every linter and guardrail rule has a positive and a negative case."""
from app.linter.guardrails import csr_hard_block, evaluate_guardrails
from app.linter.rules import Severity, lint_manifests
from app.settings import Settings


def role(rules, kind="Role", name="r", ns="ns", labels=None):
    md = {"name": name}
    if kind == "Role":
        md["namespace"] = ns
    if labels:
        md["labels"] = labels
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
            "metadata": md, "rules": rules}


def binding(role_name="r", subjects=None, kind="RoleBinding", ref_kind="Role", ns="ns"):
    md = {"name": "b"}
    if kind == "RoleBinding":
        md["namespace"] = ns
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": md,
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": ref_kind,
                        "name": role_name},
            "subjects": subjects or [{"kind": "Group", "name": "devs",
                                      "apiGroup": "rbac.authorization.k8s.io"}]}


def ids(findings):
    return {f.rule_id for f in findings}


def test_critical_rules():
    fs = lint_manifests([binding("cluster-admin", ref_kind="ClusterRole")])
    assert "RL-C1" in ids(fs)
    fs = lint_manifests([binding(subjects=[{"kind": "Group", "name": "system:masters"}])])
    assert "RL-C2" in ids(fs)
    fs = lint_manifests([role([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])])
    assert "RL-C3" in ids(fs)
    # secrets read via CRB -> critical
    cr = role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}],
              kind="ClusterRole", name="secret-reader")
    crb = binding("secret-reader", kind="ClusterRoleBinding", ref_kind="ClusterRole")
    assert "RL-C4" in ids(lint_manifests([cr, crb]))


def test_high_rules():
    assert "RL-H1" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}])]))
    assert "RL-H2" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}])]))
    assert "RL-H3" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}])]))
    assert "RL-H4" in ids(lint_manifests([role([{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["bind"]}])]))
    assert "RL-H5" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"]}])]))
    assert "RL-H6" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]}])]))
    assert "RL-H8" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}])]))
    assert "RL-H9" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["create"]}])]))
    assert "RL-H10" in ids(lint_manifests([role([{"apiGroups": ["admissionregistration.k8s.io"], "resources": ["mutatingwebhookconfigurations"], "verbs": ["update"]}])]))
    assert "RL-H11" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}])]))
    assert "RL-H12" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
        kind="ClusterRole", labels={"rbac.authorization.k8s.io/aggregate-to-view": "true"})]))
    assert "RL-H13" in ids(lint_manifests([binding(subjects=[{"kind": "Group", "name": "system:authenticated"}])]))


def test_medium_rules():
    assert "RL-M1" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])]))
    assert "RL-M2" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["namespaces"], "verbs": ["patch"]}])]))
    assert "RL-M5" in ids(lint_manifests([role([{"apiGroups": [""], "resources": ["pods"], "verbs": ["deletecollection"]}])]))
    assert "RL-M6" in ids(lint_manifests([binding(subjects=[{"kind": "ServiceAccount", "name": "default", "namespace": "ns"}])]))
    sa = {"apiVersion": "v1", "kind": "ServiceAccount",
          "metadata": {"name": "s", "namespace": "ns"}, "automountServiceAccountToken": True}
    assert "RL-M8" in ids(lint_manifests([sa]))


def test_negative_case_clean_role():
    fs = lint_manifests([role([{"apiGroups": [""], "resources": ["pods"],
                                "verbs": ["get", "list", "watch"],
                                "resourceNames": []}],
                              name="clean")])
    assert not any(f.severity in (Severity.critical, Severity.high) for f in fs)


def test_guardrails_hard_blocks():
    d = evaluate_guardrails([binding(subjects=[{"kind": "User", "name": "system:anonymous"}])])
    assert d.hard_blocks and not d.allowed
    d = evaluate_guardrails([role([{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
                                  kind="ClusterRole", name="rbac-builder-operator")])
    assert d.hard_blocks


def test_guardrails_override_required():
    d = evaluate_guardrails([binding("cluster-admin", ref_kind="ClusterRole")])
    assert not d.hard_blocks and d.override_required
    d = evaluate_guardrails([role([{"apiGroups": ["rbac.authorization.k8s.io"],
                                    "resources": ["clusterroles"], "verbs": ["escalate"]}])])
    assert d.override_required


def test_guardrails_allowed():
    d = evaluate_guardrails([role([{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}])])
    assert d.allowed


def test_csr_hard_block_sec83():
    assert csr_hard_block("system:admin", []) is not None
    assert csr_hard_block("alice", ["system:masters"]) is not None
    assert csr_hard_block("alice", ["system:nodes"]) is not None
    assert csr_hard_block("alice", ["dev-team"]) is None


def test_listed_objects_carry_kind_for_the_linter():
    """Items inside a Kubernetes List omit apiVersion/kind; list_rbac_objects
    must restore them or the live-cluster lint silently finds nothing."""
    from app.k8s import operations as ops

    class _Item:
        pass

    class _FakeApi:
        @staticmethod
        def sanitize_for_serialization(item):
            # what the real client returns for a listed object: no kind
            return {"metadata": {"name": "wild"},
                    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}

    class _FakeRbac:
        def __init__(self, *a, **k):
            pass

        def _list(self, **kwargs):
            return type("L", (), {"items": [_Item()]})()

        list_role_for_all_namespaces = _list
        list_cluster_role = _list
        list_role_binding_for_all_namespaces = _list
        list_cluster_role_binding = _list

    import app.k8s.operations as mod
    original = mod.k8s.RbacAuthorizationV1Api
    mod.k8s.RbacAuthorizationV1Api = _FakeRbac
    try:
        out = ops.list_rbac_objects(_FakeApi(), Settings(_env_file=None))
    finally:
        mod.k8s.RbacAuthorizationV1Api = original

    assert out["clusterroles"][0]["kind"] == "ClusterRole"
    assert out["roles"][0]["kind"] == "Role"
    # and the linter must now actually flag the wildcard rule
    findings = lint_manifests(out["clusterroles"])
    assert any(f.rule_id == "RL-C3" for f in findings), "wildcard ClusterRole not flagged"
