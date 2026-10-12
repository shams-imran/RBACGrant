"""Uploaded kubeconfig validation. Every uploaded or pre-registered
kubeconfig is untrusted input; it is processed in memory only."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import shutil
import socket
from dataclasses import dataclass, field
from fnmatch import fnmatch
from urllib.parse import urlparse

from ruamel.yaml import YAML
from ruamel.yaml.constructor import SafeConstructor

from ..settings import Settings

MAX_KUBECONFIG_SIZE = 256 * 1024
MAX_YAML_ALIASES = 50             # anti "billion laughs"

FILE_REF_FIELDS = ("certificate-authority", "client-certificate", "client-key", "tokenFile")

METADATA_IPS = {"169.254.169.254"}
METADATA_V6 = ipaddress.ip_network("fd00:ec2::254/128")


class KubeconfigValidationError(ValueError):
    """Rejection with a generic, content-free message (, §9)."""


@dataclass
class ValidatedKubeconfig:
    normalized_yaml: str          # single-context kubeconfig
    context_name: str
    cluster_name: str
    user_name: str
    server_url: str
    ca_sha256: str
    credential_type: str          # client-cert | token | exec
    insecure_tls: bool
    exec_command: str | None = None
    exec_args: list[str] = field(default_factory=list)
    contexts_available: list[str] = field(default_factory=list)


def _limited_safe_load(text: str) -> dict:
    """Safe loader, no custom tags, bounded alias expansion."""

    class _Constructor(SafeConstructor):
        pass

    alias_count = 0
    original = _Constructor.compose_node if hasattr(_Constructor, "compose_node") else None

    yaml = YAML(typ="safe", pure=True)
    # ruamel safe loader ignores custom tags already; bound aliases by node count.
    data = None
    try:
        # Count anchors/aliases cheaply before parse.
        if text.count("*") > MAX_YAML_ALIASES and text.count("&") > 0:
            raise KubeconfigValidationError("kubeconfig rejected")
        data = yaml.load(text)
    except KubeconfigValidationError:
        raise
    except Exception as exc:
        raise KubeconfigValidationError("kubeconfig rejected") from exc
    if not isinstance(data, dict):
        raise KubeconfigValidationError("kubeconfig rejected")
    return data


def _resolve_and_check_ssrf(server_url: str, settings: Settings) -> None:
    """Reject metadata/link-local/loopback targets before any connect."""
    parsed = urlparse(server_url)
    host = parsed.hostname
    if not host:
        raise KubeconfigValidationError("kubeconfig rejected")
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
        addresses = {info[4][0] for info in infos}
    except socket.gaierror as exc:
        raise KubeconfigValidationError(
            "the API server hostname could not be resolved"
        ) from exc
    for addr_s in addresses:
        addr = ipaddress.ip_address(addr_s.split("%")[0])
        if addr_s in METADATA_IPS or (addr.version == 6 and addr in METADATA_V6):
            raise KubeconfigValidationError("kubeconfig rejected")
        if addr.is_link_local:
            raise KubeconfigValidationError("kubeconfig rejected")
        if addr.is_loopback and not settings.allow_loopback_api_servers:
            raise KubeconfigValidationError(
                "the API server resolves to loopback; set "
                "RBAC_UI_ALLOW_LOOPBACK_API_SERVERS=true for kind/minikube"
            )
    if settings.allowed_api_servers:
        allowed = [a.strip() for a in settings.allowed_api_servers.split(",") if a.strip()]
        ok = False
        for pattern in allowed:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                if any(ipaddress.ip_address(a.split("%")[0]) in network for a in addresses):
                    ok = True
            except ValueError:
                if fnmatch(host, pattern):
                    ok = True
        if not ok:
            raise KubeconfigValidationError(
                "the API server is not on the RBAC_UI_ALLOWED_API_SERVERS allowlist"
            )


def validate_kubeconfig(
    raw: bytes, settings: Settings, *, chosen_context: str | None = None
) -> tuple[ValidatedKubeconfig, dict]:
    if len(raw) > MAX_KUBECONFIG_SIZE:
        raise KubeconfigValidationError("kubeconfig rejected")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KubeconfigValidationError("kubeconfig rejected") from exc

    data = _limited_safe_load(text)
    if data.get("kind") != "Config" or data.get("apiVersion") != "v1":
        raise KubeconfigValidationError("kubeconfig rejected")

    contexts = {c.get("name"): c.get("context", {}) for c in data.get("contexts") or []}
    clusters = {c.get("name"): c.get("cluster", {}) for c in data.get("clusters") or []}
    users = {u.get("name"): u.get("user", {}) for u in data.get("users") or []}
    if not contexts or not clusters or not users:
        raise KubeconfigValidationError("kubeconfig rejected")

    names = list(contexts)
    if chosen_context is None:
        if len(names) == 1:
            chosen_context = names[0]
        elif data.get("current-context") in contexts:
            chosen_context = data["current-context"]
        else:
            raise KubeconfigValidationError(
                "the file has several contexts; pick one"
            )
    if chosen_context not in contexts:
        raise KubeconfigValidationError("kubeconfig rejected")

    ctx = contexts[chosen_context]
    cluster = clusters.get(ctx.get("cluster"))
    user = users.get(ctx.get("user"))
    if cluster is None or user is None:
        raise KubeconfigValidationError("kubeconfig rejected")

    # No local file references, anywhere.
    for section in (cluster, user):
        for bad in FILE_REF_FIELDS:
            if bad in section:
                raise KubeconfigValidationError("kubeconfig rejected")

    # Exec / auth-provider plugins.
    exec_command: str | None = None
    exec_args: list[str] = []
    credential_type = "token" if "token" in user else None
    if "auth-provider" in user:
        raise KubeconfigValidationError("kubeconfig rejected")
    if "exec" in user:
        allowlist = [
            p.strip() for p in (settings.allowed_exec_plugins or "").split(",") if p.strip()
        ]
        if not allowlist:
            raise KubeconfigValidationError("kubeconfig rejected")
        exec_spec = user["exec"] or {}
        command = exec_spec.get("command", "")
        if "/" in command or "\\" in command:
            # relative/absolute paths rejected; basenames only
            raise KubeconfigValidationError("kubeconfig rejected")
        if command not in allowlist:
            raise KubeconfigValidationError("kubeconfig rejected")
        if shutil.which(command) is None:
            raise KubeconfigValidationError(
                "the exec plugin is allowlisted but not installed on the server"
            )
        exec_command = command
        exec_args = list(exec_spec.get("args") or [])
        # Env entries from the file are not passed through.
        exec_spec.pop("env", None)
        credential_type = "exec"
    if credential_type is None:
        if "client-certificate-data" in user and "client-key-data" in user:
            credential_type = "client-cert"
        else:
            raise KubeconfigValidationError("kubeconfig rejected")

    # TLS checks.
    insecure = bool(cluster.get("insecure-skip-tls-verify"))
    if insecure and not settings.allow_insecure_cluster_tls:
        raise KubeconfigValidationError("kubeconfig rejected")
    server = cluster.get("server", "")
    if not server.startswith("https://"):
        raise KubeconfigValidationError("kubeconfig rejected")
    if "proxy-url" in cluster:
        raise KubeconfigValidationError("kubeconfig rejected")

    _resolve_and_check_ssrf(server, settings)

    ca_data = cluster.get("certificate-authority-data", "")
    if ca_data:
        try:
            ca_sha = hashlib.sha256(base64.b64decode(ca_data)).hexdigest()
        except Exception as exc:  # noqa: BLE001
            raise KubeconfigValidationError("kubeconfig rejected") from exc
    else:
        if not insecure:
            raise KubeconfigValidationError("kubeconfig rejected")
        ca_sha = ""

    return ValidatedKubeconfig(
        normalized_yaml="",  # filled by normalize() once the final name is known
        context_name=chosen_context,
        cluster_name=ctx.get("cluster", ""),
        user_name=ctx.get("user", ""),
        server_url=server,
        ca_sha256=ca_sha,
        credential_type=credential_type,
        insecure_tls=insecure,
        exec_command=exec_command,
        exec_args=exec_args,
        contexts_available=names,
    ), data


def normalize_kubeconfig(data: dict, validated: ValidatedKubeconfig, new_name: str) -> str:
    """Keep only the chosen cluster/user/context, renamed to new_name."""
    ctx = next(c["context"] for c in data["contexts"] if c["name"] == validated.context_name)
    cluster = next(c for c in data["clusters"] if c["name"] == ctx["cluster"])
    user = next(u for u in data["users"] if u["name"] == ctx["user"])

    user_body = dict(user["user"])
    if "exec" in user_body:
        user_body["exec"].pop("env", None)

    normalized = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": new_name, "cluster": dict(cluster["cluster"])}],
        "users": [{"name": new_name, "user": user_body}],
        "contexts": [{
            "name": new_name,
            "context": {"cluster": new_name, "user": new_name,
                        **({"namespace": ctx["namespace"]} if ctx.get("namespace") else {})},
        }],
        "current-context": new_name,
    }
    import io
    yaml = YAML(typ="safe", pure=True)
    yaml.default_flow_style = False
    buf = io.StringIO()
    yaml.dump(normalized, buf)
    return buf.getvalue()
