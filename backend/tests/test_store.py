"""Local encrypted store tests."""
import base64
import secrets

import pytest

from app.models.cluster import ClusterMetadata
from app.secrets.provider import SecretProvider
from app.settings import Settings, StartupError
from app.store.base import ClusterStoreError
from app.store.local_encrypted import LocalEncryptedStore

FIXTURE_KUBECONFIG = """\
apiVersion: v1
kind: Config
clusters:
- name: c1
  cluster:
    server: https://k8s.example.internal:6443
    certificate-authority-data: aGVsbG8=
users:
- name: c1
  user:
    token: canary-fixture-token-abc123
contexts:
- name: c1
  context: {cluster: c1, user: c1}
current-context: c1
"""


def make_store(tmp_path, monkeypatch, key=None):
    key = key or base64.b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setenv("STORE_TEST_KEY", key)
    settings = Settings(cluster_store="local", store_key_ref="env:STORE_TEST_KEY",
                        data_dir=str(tmp_path / "data"))
    return LocalEncryptedStore(settings, SecretProvider(settings)), key


def md(name="c1"):
    return ClusterMetadata(name=name, serverUrl="https://k8s.example.internal:6443",
                           caSha256="ab" * 32)


def test_roundtrip(tmp_path, monkeypatch):
    store, _ = make_store(tmp_path, monkeypatch)
    store.put("c1", FIXTURE_KUBECONFIG, md())
    assert store.get_kubeconfig("c1") == FIXTURE_KUBECONFIG
    assert store.get_metadata("c1").name == "c1"
    assert store.list_names() == ["c1"]


def test_no_plaintext_on_disk(tmp_path, monkeypatch):
    """9: grep the data dir for secrets — zero hits."""
    store, _ = make_store(tmp_path, monkeypatch)
    store.put("c1", FIXTURE_KUBECONFIG, md())
    for f in (tmp_path / "data").rglob("*"):
        if f.is_file():
            blob = f.read_bytes()
            for needle in (b"canary-fixture-token", b"k8s.example.internal",
                           b"client-key-data", b"BEGIN"):
                assert needle not in blob, f"{needle} leaked into {f}"


def test_tamper_detection(tmp_path, monkeypatch):
    store, _ = make_store(tmp_path, monkeypatch)
    store.put("c1", FIXTURE_KUBECONFIG, md())
    path = tmp_path / "data" / "clusters" / "c1.kcfg.enc"
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))
    with pytest.raises(ClusterStoreError):
        store.get_kubeconfig("c1")


def test_swapped_files_fail(tmp_path, monkeypatch):
    """The cluster name is AEAD associated data."""
    store, _ = make_store(tmp_path, monkeypatch)
    store.put("c1", FIXTURE_KUBECONFIG, md("c1"))
    store.put("c2", FIXTURE_KUBECONFIG, md("c2"))
    d = tmp_path / "data" / "clusters"
    a, b = d / "c1.kcfg.enc", d / "c2.kcfg.enc"
    blob_a, blob_b = a.read_bytes(), b.read_bytes()
    a.write_bytes(blob_b)
    b.write_bytes(blob_a)
    with pytest.raises(ClusterStoreError):
        store.get_kubeconfig("c1")


def test_wrong_key_refuses(tmp_path, monkeypatch):
    monkeypatch.setenv("BAD_KEY", "not-base64-!!")
    settings = Settings(cluster_store="local", store_key_ref="env:BAD_KEY",
                        data_dir=str(tmp_path / "data"))
    with pytest.raises(StartupError):
        LocalEncryptedStore(settings, SecretProvider(settings))


def test_missing_key_refuses(tmp_path):
    settings = Settings(cluster_store="local", store_key_ref=None,
                        data_dir=str(tmp_path / "data"))
    with pytest.raises(StartupError):
        LocalEncryptedStore(settings, SecretProvider(settings))


def test_key_inside_data_dir_refused(tmp_path):
    from app.settings import validate_startup
    key_file = tmp_path / "data" / "key"
    settings = Settings(cluster_store="local", store_key_ref=f"file:{key_file}",
                        data_dir=str(tmp_path / "data"), auth_mode="none")
    with pytest.raises(StartupError):
        validate_startup(settings)


def test_loose_permissions_refused(tmp_path, monkeypatch):
    store, key = make_store(tmp_path, monkeypatch)
    store.put("c1", FIXTURE_KUBECONFIG, md())
    (tmp_path / "data" / "clusters" / "c1.kcfg.enc").chmod(0o644)
    with pytest.raises(StartupError):
        make_store(tmp_path, monkeypatch, key=key)


def test_rotate_key_roundtrip(tmp_path, monkeypatch):
    store, _ = make_store(tmp_path, monkeypatch)
    store.put("c1", FIXTURE_KUBECONFIG, md())
    new_key = base64.b64encode(secrets.token_bytes(32)).decode()
    assert store.rotate_key(new_key) == 1
    assert store.get_kubeconfig("c1") == FIXTURE_KUBECONFIG
    # reopening with the new key works
    store2, _ = make_store(tmp_path, monkeypatch, key=new_key)
    assert store2.get_kubeconfig("c1") == FIXTURE_KUBECONFIG
    assert store2.verify_all() == {"c1": "ok"}


def test_delete_removes_file(tmp_path, monkeypatch):
    store, _ = make_store(tmp_path, monkeypatch)
    store.put("c1", FIXTURE_KUBECONFIG, md())
    store.delete("c1")
    assert store.list_names() == []
    assert not (tmp_path / "data" / "clusters" / "c1.kcfg.enc").exists()
