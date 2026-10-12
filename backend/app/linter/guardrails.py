"""Guardrails on apply: hard blocks with no override, and overridable
blocks that need a typed reason, step-up and the admin role."""
from __future__ import annotations

from pydantic import BaseModel

from .rules import Finding, Severity, lint_manifests

OPERATOR_OBJECT_NAMES = {"rbac-builder-operator", "rbac-builder-operator-binding"}
HARD_BLOCK_SUBJECTS = {"system:unauthenticated", "system:anonymous"}
ESCALATION_VERBS = {"bind", "escalate", "impersonate"}


class GuardrailDecision(BaseModel):
    allowed: bool
    hard_blocks: list[str]
    override_required: list[str]
    findings: list[Finding]

    @property
    def needs_override(self) -> bool:
        return bool(self.override_required)


def evaluate_guardrails(manifests: list[dict]) -> GuardrailDecision:
    hard: list[str] = []
    override: list[str] = []
    findings = lint_manifests(manifests)

    for m in manifests:
        kind = m.get("kind", "")
        name = m.get("metadata", {}).get("name", "")

        # Hard: editing the tool's own operator objects from the UI.
        if name in OPERATOR_OBJECT_NAMES and kind in (
            "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding",
        ):
            hard.append(
                f"{kind} {name!r} is the tool's own operator identity and cannot "
                "be edited from the UI"
            )

        if kind in ("RoleBinding", "ClusterRoleBinding"):
            for s in m.get("subjects", []) or []:
                if s.get("name") in HARD_BLOCK_SUBJECTS:
                    hard.append(
                        f"{kind} {name!r} binds {s['name']!r}: granting rights to "
                        "unauthenticated identities is never allowed"
                    )
            if m.get("roleRef", {}).get("name") == "cluster-admin":
                override.append(f"{kind} {name!r} binds cluster-admin")

        if kind in ("Role", "ClusterRole"):
            for rule in m.get("rules") or []:
                verbs = set(rule.get("verbs", []))
                granted = verbs & ESCALATION_VERBS
                if granted:
                    override.append(
                        f"{kind} {name!r} grants {', '.join(sorted(granted))}"
                    )

    for f in findings:
        if f.severity == Severity.critical:
            desc = f"{f.object_kind} {f.object_name!r}: {f.message}"
            if desc not in override and not any(f.object_name in h for h in hard):
                override.append(desc)

    return GuardrailDecision(
        allowed=not hard and not override,
        hard_blocks=hard,
        override_required=override,
        findings=findings,
    )


def csr_hard_block(common_name: str, groups: list[str]) -> str | None:
    """No override for system:* identities in CSRs."""
    if common_name.startswith("system:"):
        return f"CN {common_name!r} starts with 'system:' and is hard-blocked"
    for g in groups:
        if g == "system:masters" or g.startswith("system:"):
            return f"group {g!r} is a system group and is hard-blocked"
    return None
