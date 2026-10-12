"""Kubernetes client factory: decrypted kubeconfigs are used only for
the request that needs them; cert/key temp files go through a private 0700
runtime dir that is wiped on close, startup and shutdown. Never /tmp."""
from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

from kubernetes import client as k8s_client
from kubernetes.config.kube_config import KubeConfigLoader

from ruamel.yaml import YAML

from ..settings import Settings

APP_VERSION = "0.1.0"


def ensure_runtime_dir(settings: Settings) -> Path:
    path = Path(settings.runtime_dir)
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except PermissionError as exc:
        raise RuntimeError(
            f"cannot create the runtime dir {path}: its parent is not writable by "
            "this user. When running as a non-root container user, mount it owned "
            "by that user, e.g. --tmpfs /run/rbac-ui:rw,noexec,nosuid,size=16m,"
            "mode=0700,uid=10001,gid=10001"
        ) from exc

    # The directory may be supplied by the platform (a tmpfs mount, a Kubernetes
    # emptyDir) and owned by another user, so chmod is not always permitted.
    # Only tighten it when it is actually too open.
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        try:
            os.chmod(path, 0o700)
        except PermissionError as exc:
            raise RuntimeError(
                f"runtime dir {path} is group- or world-accessible and this user "
                "cannot tighten it (the mount is owned by someone else). Mount it "
                "0700 and owned by the runtime user, e.g. --tmpfs /run/rbac-ui:"
                "rw,noexec,nosuid,size=16m,mode=0700,uid=10001,gid=10001"
            ) from exc

    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError(f"runtime dir {path} must be 0700")
    return path


def wipe_runtime_dir(settings: Settings) -> None:
    path = Path(settings.runtime_dir)
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    ensure_runtime_dir(settings)


@contextlib.contextmanager
def api_client_for(kubeconfig_yaml: str, settings: Settings, app_user: str = ""):
    """Yields a configured ApiClient; wipes its temp files afterwards."""
    runtime_dir = ensure_runtime_dir(settings)
    workdir = tempfile.mkdtemp(prefix="cluster-", dir=runtime_dir)
    os.chmod(workdir, 0o700)
    try:
        yaml = YAML(typ="safe", pure=True)
        cfg_dict = yaml.load(kubeconfig_yaml)
        loader = KubeConfigLoader(config_dict=cfg_dict, temp_file_path=workdir)
        configuration = k8s_client.Configuration()
        loader.load_and_set(configuration)
        # No transport retries: must be set BEFORE ApiClient builds its urllib3
        # pool, or an unreachable cluster hangs for 3x the connect timeout.
        configuration.retries = 0
        # Attribution header plus a per-request timeout.
        api = k8s_client.ApiClient(configuration)
        api.user_agent = f"rbacgrant/{APP_VERSION} (app-user={app_user})"
        yield api
        api.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def request_timeout(settings: Settings) -> int:
    return settings.k8s_timeout_s
