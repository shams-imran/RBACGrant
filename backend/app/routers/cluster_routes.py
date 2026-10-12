"""Cluster registry: list, add-wizard validation, save, replace,
rename, delete. Credentials are write-only from the UI."""
from __future__ import annotations

import base64
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..models.cluster import ClusterMetadata, Environment
from ..models.rbac import DNS1123_LABEL
from ..security.audit import get_audit
from ..security.deps import get_client_ip, require, require_step_up
from ..settings import get_settings
from ..store.base import ClusterNotFound, ClusterStoreError
from ..store.kubeconfig_validation import (
    KubeconfigValidationError, normalize_kubeconfig, validate_kubeconfig,
)
from ..store.registry import get_registry

router = APIRouter(prefix="/api/clusters", tags=["clusters"])


def _visible(session, name: str) -> bool:
    from ..auth.service import get_auth_service
    return get_auth_service().user_can_see_cluster(session.clusters, name)


def _audit_ctx(request: Request, session) -> dict:
    return {"user": session.username, "source_ip": get_client_ip(request),
            "request_id": request.state.request_id}


@router.get("")
async def list_clusters(request: Request, session=require("clusters:view")) -> dict:
    registry = get_registry()
    out = []
    for name in registry.list_names():
        if not _visible(session, name):
            continue  # invisible
        try:
            md = registry.get_metadata(name)
        except (ClusterStoreError, ClusterNotFound, KubeconfigValidationError):
            out.append({"metadata": {"name": name}, "connectionStatus": "error"})
            continue
        out.append({
            "metadata": md.model_dump(mode="json"),
            "lastUsed": registry.last_used(name),
            "connectionStatus": "unknown",
        })
    return {"clusters": out, "storeBackend": registry.backend_name}


def _cert_row(label: str, cert) -> dict:
    """One row shaped like `kubeadm certs check-expiration` output."""
    not_after = cert.not_valid_after_utc
    return {
        "name": label,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "notAfter": not_after.isoformat(),
        "daysLeft": max(0, (not_after - datetime.now(timezone.utc)).days),
    }


@router.get("/{name}/certs")
async def cluster_certs(name: str, request: Request,
                        session=require("clusters:view")) -> dict:
    """Remote equivalent of `kubeadm certs check-expiration`: CA cert(s) from
    the stored kubeconfig, the API server's serving cert via a TLS handshake,
    and the stored client credential if it is a certificate."""
    import socket
    import ssl
    from urllib.parse import urlparse

    import yaml
    from cryptography import x509

    registry = get_registry()
    if not _visible(session, name) or name not in registry.list_names():
        raise HTTPException(status_code=404, detail="cluster not found")
    kc = yaml.safe_load(registry.get_kubeconfig(name))
    cluster = kc["clusters"][0]["cluster"]
    user = kc["users"][0]["user"]
    rows: list[dict] = []
    errors: list[str] = []

    ca_b64 = cluster.get("certificate-authority-data")
    if ca_b64:
        try:
            for i, c in enumerate(
                    x509.load_pem_x509_certificates(base64.b64decode(ca_b64))):
                rows.append(_cert_row(f"cluster CA{f' #{i + 1}' if i else ''}", c))
        except Exception:  # noqa: BLE001
            errors.append("could not parse the CA certificate")

    # Serving cert of the API server (the stored, already-SSRF-checked URL).
    try:
        u = urlparse(cluster.get("server", ""))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # read-only inspection, not a trust decision
        with socket.create_connection((u.hostname, u.port or 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=u.hostname) as tls:
                der = tls.getpeercert(binary_form=True)
        if der:
            rows.append(_cert_row("API server (serving cert)",
                                  x509.load_der_x509_certificate(der)))
    except Exception:  # noqa: BLE001
        errors.append("could not reach the API server for its serving certificate")

    cc_b64 = user.get("client-certificate-data")
    if cc_b64:
        try:
            rows.append(_cert_row(
                "stored admin credential (client cert)",
                x509.load_pem_x509_certificates(base64.b64decode(cc_b64))[0]))
        except Exception:  # noqa: BLE001
            errors.append("could not parse the stored client certificate")

    return {"certificates": rows, "errors": errors}


@router.get("/{name}")
async def get_cluster(name: str, request: Request, session=require("clusters:view")) -> dict:
    registry = get_registry()
    if not _visible(session, name) or name not in registry.list_names():
        raise HTTPException(status_code=404, detail="cluster not found")
    md = registry.get_metadata(name)
    return {"metadata": md.model_dump(mode="json"), "lastUsed": registry.last_used(name)}


class ValidateBody(BaseModel):
    kubeconfig: str = Field(max_length=262144)
    context: str | None = None


@router.post("/validate")
async def validate_upload(body: ValidateBody, request: Request,
                          session=require("clusters:manage")) -> dict:
    """Wizard step 2/3: validation + context pick. In-memory only."""
    settings = get_settings()
    try:
        validated, _ = validate_kubeconfig(
            body.kubeconfig.encode(), settings, chosen_context=body.context)
    except KubeconfigValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry = get_registry()
    duplicate = registry.find_duplicate(validated.server_url, validated.ca_sha256)
    return {
        "contextsAvailable": validated.contexts_available,
        "context": validated.context_name,
        "suggestedName": validated.context_name if DNS1123_LABEL.match(validated.context_name)
                         else "my-cluster",
        "serverUrl": validated.server_url,
        "caSha256": validated.ca_sha256,
        "credentialType": validated.credential_type,
        "tlsVerified": not validated.insecure_tls,
        "execCommand": validated.exec_command,   # shown before saving
        "execArgs": validated.exec_args,
        "duplicateOf": duplicate,
    }


class SaveBody(BaseModel):
    kubeconfig: str = Field(max_length=262144)
    context: str | None = None
    name: str = Field(min_length=1, max_length=63)
    displayName: str = ""
    environment: Environment = "other"
    description: str = ""
    publicApiUrl: str | None = None


@router.post("")
async def add_cluster(body: SaveBody, request: Request,
                      session=require("clusters:manage")) -> dict:
    """Wizard final step: step-up, validate again, normalize, save."""
    require_step_up(request, session)
    settings = get_settings()
    registry = get_registry()
    if not DNS1123_LABEL.match(body.name):
        raise HTTPException(status_code=422, detail="the cluster name must be a DNS-1123 label")
    if body.name in registry.list_names():
        raise HTTPException(status_code=409, detail="a cluster with that name already exists")
    try:
        validated, raw = validate_kubeconfig(
            body.kubeconfig.encode(), settings, chosen_context=body.context)
    except KubeconfigValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    normalized = normalize_kubeconfig(raw, validated, body.name)
    now = datetime.now(timezone.utc)
    metadata = ClusterMetadata(
        name=body.name, displayName=body.displayName or body.name,
        environment=body.environment, description=body.description,
        serverUrl=validated.server_url, publicApiUrl=body.publicApiUrl,
        caSha256=validated.ca_sha256, credentialType=validated.credential_type,
        addedBy=session.username, addedAt=now, updatedBy=session.username,
        updatedAt=now, storeBackend=registry.backend_name,
        tlsVerified=not validated.insecure_tls,
    )
    try:
        registry.put(body.name, normalized, metadata)
    except (ClusterStoreError, PermissionError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    get_audit().emit("cluster.add", cluster=body.name, **_audit_ctx(request, session))
    return {"ok": True, "name": body.name}


class ReplaceBody(BaseModel):
    kubeconfig: str = Field(max_length=262144)
    context: str | None = None
    acknowledgeChanges: bool = False


@router.post("/{name}/replace")
async def replace_credentials(name: str, body: ReplaceBody, request: Request,
                              session=require("clusters:manage")) -> dict:
    """Rotation swaps the credential; warn when server URL/CA changed."""
    require_step_up(request, session)
    settings = get_settings()
    registry = get_registry()
    if name not in registry.list_names() or not _visible(session, name):
        raise HTTPException(status_code=404, detail="cluster not found")
    old_md = registry.get_metadata(name)
    try:
        validated, raw = validate_kubeconfig(
            body.kubeconfig.encode(), settings, chosen_context=body.context)
    except KubeconfigValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    changes = []
    if validated.server_url != old_md.serverUrl:
        changes.append({"field": "serverUrl", "old": old_md.serverUrl,
                        "new": validated.server_url})
    if validated.ca_sha256 != old_md.caSha256:
        changes.append({"field": "caSha256", "old": old_md.caSha256,
                        "new": validated.ca_sha256})
    if changes and not body.acknowledgeChanges:
        return {"ok": False, "requiresAcknowledgement": True, "changes": changes,
                "warning": "rotation swaps the credential; it must not silently "
                           "repoint the cluster"}

    normalized = normalize_kubeconfig(raw, validated, name)
    metadata = old_md.model_copy(update={
        "serverUrl": validated.server_url, "caSha256": validated.ca_sha256,
        "credentialType": validated.credential_type,
        "updatedBy": session.username, "updatedAt": datetime.now(timezone.utc),
        "tlsVerified": not validated.insecure_tls,
    })
    registry.put(name, normalized, metadata)
    get_audit().emit("cluster.replace", cluster=name, **_audit_ctx(request, session),
                     changed_fields=[c["field"] for c in changes])
    return {"ok": True, "changes": changes}


class RenameBody(BaseModel):
    newName: str = Field(min_length=1, max_length=63)


@router.post("/{name}/rename")
async def rename_cluster(name: str, body: RenameBody, request: Request,
                         session=require("clusters:manage")) -> dict:
    require_step_up(request, session)
    registry = get_registry()
    if name not in registry.list_names() or not _visible(session, name):
        raise HTTPException(status_code=404, detail="cluster not found")
    if not DNS1123_LABEL.match(body.newName):
        raise HTTPException(status_code=422, detail="the new name must be a DNS-1123 label")
    try:
        registry.rename(name, body.newName)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    get_audit().emit("cluster.rename", cluster=name, target=body.newName,
                     **_audit_ctx(request, session))
    return {"ok": True, "name": body.newName}


class DeleteBody(BaseModel):
    confirmName: str


@router.post("/{name}/delete")
async def delete_cluster(name: str, body: DeleteBody, request: Request,
                         session=require("clusters:manage")) -> dict:
    """Step-up plus typing the cluster name; destroys all versions."""
    require_step_up(request, session)
    registry = get_registry()
    if name not in registry.list_names() or not _visible(session, name):
        raise HTTPException(status_code=404, detail="cluster not found")
    if body.confirmName != name:
        raise HTTPException(status_code=422,
                            detail="type the cluster name exactly to confirm deletion")
    try:
        registry.delete(name)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    get_audit().emit("cluster.delete", cluster=name, **_audit_ctx(request, session))
    return {"ok": True}
