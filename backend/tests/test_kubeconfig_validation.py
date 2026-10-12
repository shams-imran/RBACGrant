"""Upload validation: each attack is rejected with a generic
error that does not echo the content."""
import pytest

from app.settings import Settings
from app.store.kubeconfig_validation import (
    KubeconfigValidationError, normalize_kubeconfig, validate_kubeconfig,
)


def settings(**kw):
    return Settings(auth_mode="none", allow_loopback_api_servers=kw.pop("loopback", False), **kw)


BASE = """\
apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: {server}
    certificate-authority-data: aGVsbG8=
users:
- name: test
  user:
    {user}
contexts:
- name: test
  context: {{cluster: test, user: test}}
current-context: test
"""


def cfg(server="https://93.184.216.34:6443", user="token: secret-token-xyz"):
    return BASE.format(server=server, user=user).encode()


def assert_rejected(raw: bytes, s=None, needle=None):
    with pytest.raises(KubeconfigValidationError) as exc:
        validate_kubeconfig(raw, s or settings())
    msg = str(exc.value)
    if needle:
        assert needle not in msg  # content never echoed back
    return msg


def test_exec_plugin_rejected_by_default():
    assert_rejected(cfg(user="exec: {command: aws, args: [eks, get-token]}"), needle="aws")


def test_auth_provider_rejected():
    assert_rejected(cfg(user="auth-provider: {name: gcp}"))


def test_file_refs_rejected():
    assert_rejected(cfg(user="client-key: /etc/passwd"), needle="/etc/passwd")
    assert_rejected(cfg(user="tokenFile: /var/run/secrets/token"))


def test_insecure_tls_rejected():
    raw = cfg().replace(b"certificate-authority-data: aGVsbG8=",
                        b"insecure-skip-tls-verify: true")
    assert_rejected(raw)


def test_http_server_rejected():
    assert_rejected(cfg(server="http://93.184.216.34:6443"))


def test_metadata_ip_rejected():
    assert_rejected(cfg(server="https://169.254.169.254"))


def test_link_local_rejected():
    assert_rejected(cfg(server="https://169.254.10.10:6443"))


def test_loopback_rejected_without_override():
    assert_rejected(cfg(server="https://127.0.0.1:6443"))


def test_loopback_allowed_with_override():
    validated, _ = validate_kubeconfig(cfg(server="https://127.0.0.1:6443"),
                                       settings(loopback=True))
    assert validated.server_url == "https://127.0.0.1:6443"


def test_oversize_rejected():
    assert_rejected(b"x" * (256 * 1024 + 1))


def test_alias_bomb_rejected():
    bomb = "a: &a [x]\n" + "\n".join(f"k{i}: *a" for i in range(200))
    assert_rejected(bomb.encode())


def test_not_a_config_rejected():
    assert_rejected(b"apiVersion: v1\nkind: Pod\nmetadata: {name: x}")


def test_exec_allowlist(monkeypatch, tmp_path):
    # allowlisted basename that resolves on PATH is accepted
    fake = tmp_path / "gke-gcloud-auth-plugin"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    s = settings(allowed_exec_plugins="gke-gcloud-auth-plugin")
    validated, _ = validate_kubeconfig(
        cfg(user="exec: {command: gke-gcloud-auth-plugin}"), s)
    assert validated.credential_type == "exec"
    # absolute path rejected even when the basename is allowlisted
    assert_rejected(cfg(user="exec: {command: /usr/bin/gke-gcloud-auth-plugin}"), s)


def test_multi_context_requires_choice():
    raw = b"""\
apiVersion: v1
kind: Config
clusters:
- {name: a, cluster: {server: "https://93.184.216.34:6443", certificate-authority-data: aGVsbG8=}}
- {name: b, cluster: {server: "https://93.184.216.35:6443", certificate-authority-data: aGVsbG8=}}
users:
- {name: ua, user: {token: t1}}
- {name: ub, user: {token: t2}}
contexts:
- {name: ctx-a, context: {cluster: a, user: ua}}
- {name: ctx-b, context: {cluster: b, user: ub}}
"""
    with pytest.raises(KubeconfigValidationError):
        validate_kubeconfig(raw, settings())
    validated, data = validate_kubeconfig(raw, settings(), chosen_context="ctx-b")
    assert validated.server_url == "https://93.184.216.35:6443"
    # Normalization: one context, renamed
    normalized = normalize_kubeconfig(data, validated, "prod-dhaka")
    assert "ctx-a" not in normalized and "t1" not in normalized
    assert "prod-dhaka" in normalized and "current-context: prod-dhaka" in normalized
