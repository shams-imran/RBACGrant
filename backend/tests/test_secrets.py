"""Secret-ref resolution, and the file permission rule in particular.

The rule has to satisfy two things at once: no other user may read a secret
file, and a platform-mounted file we cannot chmod must still be usable.
Kubernetes mounts secret volumes group-readable whenever the pod sets fsGroup,
which it has to for a writable data volume.
"""
from __future__ import annotations

import os

import pytest

from app.secrets.provider import SecretProvider, SecretRefError
from app.settings import Settings


def provider() -> SecretProvider:
    return SecretProvider(Settings(_env_file=None))


def key_file(tmp_path, mode: int, name: str = "store.key"):
    path = tmp_path / name
    path.write_text("c2VjcmV0LW1hdGVyaWFs\n")
    os.chmod(path, mode)
    return path


def test_owner_only_file_is_accepted(tmp_path):
    path = key_file(tmp_path, 0o600)
    assert provider().get(f"file:{path}").get_secret_value() == "c2VjcmV0LW1hdGVyaWFs"


def test_world_readable_is_refused(tmp_path):
    path = key_file(tmp_path, 0o644)
    with pytest.raises(SecretRefError, match="world-readable"):
        provider().get(f"file:{path}")


def test_world_readable_without_group_is_refused(tmp_path):
    """0604: no group access, but any user on the host can read it."""
    path = key_file(tmp_path, 0o604)
    with pytest.raises(SecretRefError, match="world-readable"):
        provider().get(f"file:{path}")


def test_group_readable_by_our_own_group_is_accepted(tmp_path):
    """What Kubernetes gives us: 0440, group == the pod's fsGroup == our gid."""
    path = key_file(tmp_path, 0o440)
    assert os.stat(path).st_gid in {os.getgid(), *os.getgroups()}
    assert provider().get(f"file:{path}").get_secret_value() == "c2VjcmV0LW1hdGVyaWFs"


def test_group_readable_by_a_foreign_group_is_refused(tmp_path, monkeypatch):
    """Same mode, but the group is one this process is not in."""
    path = key_file(tmp_path, 0o640)
    monkeypatch.setattr("app.secrets.provider._own_groups", lambda: {999999})
    with pytest.raises(SecretRefError, match="readable by group"):
        provider().get(f"file:{path}")


def test_setgid_bit_alone_does_not_trip_the_check(tmp_path):
    """Kubernetes sets g+s on fsGroup volumes; only the read bits matter."""
    path = key_file(tmp_path, 0o600)
    os.chmod(path, 0o2600)
    assert provider().get(f"file:{path}").get_secret_value() == "c2VjcmV0LW1hdGVyaWFs"


def test_relative_path_is_refused(tmp_path):
    with pytest.raises(SecretRefError, match="absolute path"):
        provider().get("file:relative/store.key")


def test_missing_file_names_the_ref_not_the_value(tmp_path):
    ref = f"file:{tmp_path / 'absent.key'}"
    with pytest.raises(SecretRefError) as exc:
        provider().get(ref)
    assert "does not exist" in str(exc.value)
