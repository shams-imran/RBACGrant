"""Per-cluster operations: discovery, live RBAC, dry-run, apply, delete,
can-i, identity, SA tokens and CSR signing. Every call names the cluster
explicitly — there is no hidden current context."""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets as pysecrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..generators.kubeconfig import build_kubeconfig, expiry_from_ttl, kubeconfig_filename
from ..generators.manifests import bundle_manifests, to_yaml
from ..k8s.client_factory import api_client_for
from ..k8s import operations as ops
from ..linter import evaluate_guardrails
from ..linter.rules import lint_manifests
from ..models.rbac import Bundle
from ..security.audit import get_audit
from ..security.deps import get_client_ip, require, require_step_up, require_writable
from ..settings import get_settings
from ..store.registry import get_registry

router = APIRouter(prefix="/api/clusters/{cluster}", tags=["k8s"])
log = logging.getLogger("rbac_ui.k8s")

_discovery_cache: dict[str, tuple[float, dict]] = {}
DISCOVERY_CACHE_TTL = 300


def _ca_not_after(kc_yaml: str) -> str | None:
    """Expiry of the cluster CA from the stored kubeconfig — a hard upper
    bound no issued credential can outlive. None if it cannot be determined."""
    try:
        import yaml
        from cryptography import x509
        data = yaml.safe_load(kc_yaml)
        ca_b64 = data["clusters"][0]["cluster"].get("certificate-authority-data")
        if not ca_b64:
            return None
        certs = x509.load_pem_x509_certificates(base64.b64decode(ca_b64))
        return min(c.not_valid_after_utc for c in certs).isoformat()
    except Exception:  # noqa: BLE001 — purely informational
        return None


def _api_server_cert_not_after(server_url: str) -> str | None:
    """Expiry of the API server's serving certificate, read via a TLS
    handshake to the stored (already SSRF-checked) server URL."""
    try:
        import socket
        import ssl
        from urllib.parse import urlparse

        from cryptography import x509
        u = urlparse(server_url)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # read-only inspection, not a trust decision
        with socket.create_connection((u.hostname, u.port or 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=u.hostname) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return None
        return x509.load_der_x509_certificate(der).not_valid_after_utc.isoformat()
    except Exception:  # noqa: BLE001 — purely informational
        return None


def _kubeconfig_or_404(session, cluster: str) -> str:
    from ..auth.service import get_auth_service
    registry = get_registry()
    if (cluster not in registry.list_names()
            or not get_auth_service().user_can_see_cluster(session.clusters, cluster)):
        raise HTTPException(status_code=404, detail="cluster not found")
    return registry.get_kubeconfig(cluster)


def _metadata(cluster: str):
    return get_registry().get_metadata(cluster)


def _audit_ctx(request: Request, session) -> dict:
    return {"user": session.username, "source_ip": get_client_ip(request),
            "request_id": request.state.request_id}


def _step_up_for_prod(request: Request, session, cluster: str) -> None:
    """Apply/delete on a prod-tagged cluster needs fresh step-up."""
    if _metadata(cluster).environment == "prod":
        require_step_up(request, session)


def _handle(exc: ops.K8sOperationError) -> HTTPException:
    return HTTPException(status_code=exc.status if 400 <= exc.status < 600 else 502,
                         detail=str(exc))


@router.get("/discovery")
def discovery(cluster: str, request: Request, session=require("rbac:view")) -> dict:
    settings = get_settings()
    kc = _kubeconfig_or_404(session, cluster)
    cached = _discovery_cache.get(cluster)
    if cached and time.monotonic() - cached[0] < DISCOVERY_CACHE_TTL:
        return cached[1]
    try:
        with api_client_for(kc, settings, session.username) as api:
            result = ops.discover(api, settings)
    except ops.K8sOperationError as exc:
        raise _handle(exc)
    # Auto-select the offline catalog for the fetched server version.
    from .. import catalog as catalog_pkg
    try:
        result["catalog"] = catalog_pkg.best_catalog_for(result["version"]["minor"])
    except FileNotFoundError:
        result["catalog"] = None
    result["caNotAfter"] = _ca_not_after(kc)
    result["apiServerCertNotAfter"] = _api_server_cert_not_after(
        _metadata(cluster).serverUrl)
    _discovery_cache[cluster] = (time.monotonic(), result)
    return result


@router.get("/identity")
def identity(cluster: str, request: Request, session=require("clusters:view")) -> dict:
    settings = get_settings()
    kc = _kubeconfig_or_404(session, cluster)
    try:
        with api_client_for(kc, settings, session.username) as api:
            return ops.inspect_identity(api, settings)
    except ops.K8sOperationError as exc:
        raise _handle(exc)


@router.get("/test-connection")
def test_connection(cluster: str, request: Request,
                          session=require("clusters:view")) -> dict:
    settings = get_settings()
    kc = _kubeconfig_or_404(session, cluster)
    try:
        with api_client_for(kc, settings, session.username) as api:
            version = ops.server_version(api, settings)
        log.info("connected to cluster %r (K8s %s) for user %r",
                 cluster, version.get("gitVersion", "?"), session.username)
        get_audit().emit("cluster.connect", cluster=cluster, result="ok",
                         **_audit_ctx(request, session))
        return {"ok": True, "version": version}
    except Exception as exc:  # noqa: BLE001 — connection failures are expected here
        reason = (str(exc) if isinstance(exc, ops.K8sOperationError)
                  else "connection failed")
        log.warning("cannot connect to cluster %r for user %r: %s",
                    cluster, session.username, reason)
        get_audit().emit("cluster.connect", cluster=cluster, result="error",
                         error=reason, **_audit_ctx(request, session))
        return {"ok": False, "error": reason}


@router.get("/rbac")
def live_rbac(cluster: str, request: Request, session=require("rbac:view")) -> dict:
    settings = get_settings()
    kc = _kubeconfig_or_404(session, cluster)
    try:
        with api_client_for(kc, settings, session.username) as api:
            objects = ops.list_rbac_objects(api, settings)
    except ops.K8sOperationError as exc:
        raise _handle(exc)
    all_manifests = [m for lst in objects.values() for m in lst]
    findings = lint_manifests(all_manifests)
    return {"objects": objects, "findings": [f.model_dump() for f in findings]}


@router.get("/rbac/{kind}/{name}")
@router.get("/rbac/{kind}/{namespace}/{name}")
def rbac_object(cluster: str, kind: str, name: str, request: Request,
                      namespace: str | None = None,
                      session=require("rbac:view")) -> dict:
    settings = get_settings()
    kc = _kubeconfig_or_404(session, cluster)
    try:
        with api_client_for(kc, settings, session.username) as api:
            obj = ops.get_rbac_object(api, settings, kind, name, namespace)
    except ops.K8sOperationError as exc:
        raise _handle(exc)
    return {"object": obj, "findings": [f.model_dump() for f in lint_manifests([obj])]}


class ApplyBody(BaseModel):
    bundle: Bundle
    dryRun: bool = True
    confirmClusterName: str | None = None
    overrideReason: str | None = None


@router.post("/apply")
def apply(cluster: str, body: ApplyBody, request: Request,
                session=require("rbac:apply")) -> dict:
    settings = get_settings()
    audit = get_audit()
    kc = _kubeconfig_or_404(session, cluster)
    manifests = bundle_manifests(body.bundle)
    yaml_text = to_yaml(manifests)
    sha = hashlib.sha256(yaml_text.encode()).hexdigest()

    decision = evaluate_guardrails(manifests)
    if decision.hard_blocks:
        raise HTTPException(status_code=403, detail={
            "hardBlocks": decision.hard_blocks,
            "message": "these findings are hard-blocked with no override"})

    if not body.dryRun:
        require_writable()
        md = _metadata(cluster)
        if md.environment == "prod":
            # Typed cluster name + step-up for prod.
            if body.confirmClusterName != cluster:
                raise HTTPException(status_code=422,
                                    detail="type the cluster name to apply to a prod cluster")
            require_step_up(request, session)
        if decision.override_required:
            # Typed reason + step-up + admin role.
            from ..auth.service import role_has
            if not role_has(session.role, "guardrail:override"):
                raise HTTPException(status_code=403, detail={
                    "overrideRequired": decision.override_required,
                    "message": "an admin must override these findings"})
            if not body.overrideReason or not body.overrideReason.strip():
                raise HTTPException(status_code=422, detail={
                    "overrideRequired": decision.override_required,
                    "message": "a typed reason is required to override the guardrails"})
            require_step_up(request, session)
            audit.emit("guardrail.override", cluster=cluster,
                       reason=body.overrideReason.strip(),
                       findings=decision.override_required,
                       **_audit_ctx(request, session))

    results = []
    try:
        with api_client_for(kc, settings, session.username) as api:
            if not body.dryRun:
                # Operator self-check before real applies.
                if not ops.self_can(api, settings, verb="create", resource="rolebindings",
                                    group="rbac.authorization.k8s.io"):
                    results.append({"warning": "the operator identity may lack rights "
                                               "to grant these permissions"})
            for m in manifests:
                resp = ops.server_side_apply(api, settings, m,
                                             dry_run=body.dryRun, app_user=session.username)
                results.append({
                    "kind": m["kind"], "name": m["metadata"]["name"],
                    "namespace": m["metadata"].get("namespace"),
                    "result": resp,
                })
    except ops.K8sOperationError as exc:
        audit.emit("rbac.apply" if not body.dryRun else "rbac.dry_run",
                   cluster=cluster, result="error", error_class="K8sOperationError",
                   yaml_sha256=sha, **_audit_ctx(request, session))
        raise _handle(exc)

    if not body.dryRun:
        # New roles/SAs should show up in discovery-driven pickers right away.
        _discovery_cache.pop(cluster, None)
    audit.emit("rbac.apply" if not body.dryRun else "rbac.dry_run", cluster=cluster,
               target=", ".join(f"{m['kind']}/{m['metadata']['name']}" for m in manifests),
               yaml_sha256=sha, **_audit_ctx(request, session))
    return {"dryRun": body.dryRun, "results": results,
            "guardrails": decision.model_dump()}


class DeleteObjectBody(BaseModel):
    kind: str
    name: str
    namespace: str | None = None
    confirmClusterName: str | None = None


@router.post("/delete-object")
def delete_object(cluster: str, body: DeleteObjectBody, request: Request,
                        session=require("rbac:delete")) -> dict:
    settings = get_settings()
    require_writable()
    kc = _kubeconfig_or_404(session, cluster)
    md = _metadata(cluster)
    if md.environment == "prod":
        if body.confirmClusterName != cluster:
            raise HTTPException(status_code=422,
                                detail="type the cluster name to delete on a prod cluster")
        require_step_up(request, session)
    try:
        with api_client_for(kc, settings, session.username) as api:
            ops.delete_object(api, settings, body.kind, body.name, body.namespace)
    except ops.K8sOperationError as exc:
        raise _handle(exc)
    _discovery_cache.pop(cluster, None)
    get_audit().emit("rbac.delete", cluster=cluster,
                     target=f"{body.kind}/{body.name}", **_audit_ctx(request, session))
    return {"ok": True}


class CanIBody(BaseModel):
    user: str | None = None
    groups: list[str] = Field(default_factory=list)
    serviceAccount: str | None = None    # "namespace:name"
    verb: str
    resource: str
    apiGroup: str = ""
    namespace: str | None = None
    name: str | None = None


@router.post("/can-i")
def can_i(cluster: str, body: CanIBody, request: Request,
                session=require("cani:run")) -> dict:
    settings = get_settings()
    kc = _kubeconfig_or_404(session, cluster)
    user = body.user
    groups = list(body.groups)
    if body.serviceAccount:
        ns, _, sa = body.serviceAccount.partition(":")
        user = f"system:serviceaccount:{ns}:{sa}"
        groups = [f"system:serviceaccounts:{ns}", "system:serviceaccounts"]
    try:
        with api_client_for(kc, settings, session.username) as api:
            return ops.subject_access_review(
                api, settings, user=user, groups=groups, verb=body.verb,
                resource=body.resource, group=body.apiGroup,
                namespace=body.namespace, name=body.name)
    except ops.K8sOperationError as exc:
        raise _handle(exc)


class SaTokenBody(BaseModel):
    namespace: str
    serviceAccount: str
    ttlSeconds: int | None = None
    # "never expire" is not possible for TokenRequest tokens; this issues at
    # the configured maximum (RBAC_UI_MAX_TOKEN_TTL) instead.
    neverExpire: bool = False
    defaultNamespace: str | None = None


@router.post("/kubeconfig/serviceaccount")
def sa_kubeconfig(cluster: str, body: SaTokenBody, request: Request,
                        session=require("kubeconfig:generate")) -> dict:
    """TokenRequest kubeconfig. Shown/downloaded once, never stored."""
    settings = get_settings()
    audit = get_audit()
    kc = _kubeconfig_or_404(session, cluster)
    md = _metadata(cluster)
    ttl = (settings.max_token_ttl_s if body.neverExpire
           else body.ttlSeconds or settings.default_token_ttl_s)
    if ttl > settings.max_token_ttl_s:
        raise HTTPException(status_code=422,
                            detail=f"TTL above the cap ({settings.max_token_ttl})")
    try:
        with api_client_for(kc, settings, session.username) as api:
            token_resp = ops.create_sa_token(
                api, settings, namespace=body.namespace,
                service_account=body.serviceAccount, ttl_seconds=ttl)
    except ops.K8sOperationError as exc:
        raise _handle(exc)

    # The public API URL override is what generated kubeconfigs use.
    server = md.publicApiUrl or md.serverUrl
    from ruamel.yaml import YAML
    yaml = YAML(typ="safe", pure=True)
    stored = yaml.load(kc)
    ca_b64 = stored["clusters"][0]["cluster"].get("certificate-authority-data", "")

    expires = expiry_from_ttl(token_resp["ttlSeconds"])
    subject = f"system:serviceaccount:{body.namespace}:{body.serviceAccount}"
    content = build_kubeconfig(
        cluster_name=cluster, server_url=server, ca_data_b64=ca_b64,
        user_name=subject, namespace=body.defaultNamespace or body.namespace,
        token=token_resp["token"], expires_at=expires)
    audit.emit("kubeconfig.generate", cluster=cluster, target=subject,
               ttl_seconds=token_resp["ttlSeconds"],
               expires_at=expires.isoformat(timespec="seconds"),
               **_audit_ctx(request, session))
    return {"kubeconfig": content,
            "filename": kubeconfig_filename(cluster, subject, expires),
            "expiresAt": expires.isoformat(timespec="seconds"),
            "warning": "an issued TokenRequest token cannot be revoked before it "
                       "expires; cutting access early means deleting the "
                       "ServiceAccount or removing its bindings"}


class CsrBody(BaseModel):
    commonName: str
    groups: list[str] = Field(default_factory=list)
    csrPem: str = Field(max_length=65536)   # key stays in the browser
    ttlSeconds: int | None = None
    neverExpire: bool = False               # = issue at the max cap
    defaultNamespace: str | None = None


@router.post("/kubeconfig/user-csr")
def user_csr(cluster: str, body: CsrBody, request: Request,
                   session=require("kubeconfig:generate")) -> dict:
    """Sign a browser-generated CSR and return cert + cluster details.
    The kubeconfig is assembled client-side so the key never reaches the server."""
    settings = get_settings()
    audit = get_audit()
    from ..linter.guardrails import csr_hard_block
    block = csr_hard_block(body.commonName, body.groups)
    if block:
        raise HTTPException(status_code=403, detail=block)
    kc = _kubeconfig_or_404(session, cluster)
    md = _metadata(cluster)
    ttl = (settings.max_cert_ttl_s if body.neverExpire
           else body.ttlSeconds or settings.default_cert_ttl_s)
    if ttl > settings.max_cert_ttl_s:
        raise HTTPException(status_code=422,
                            detail=f"TTL above the cap ({settings.max_cert_ttl})")
    csr_name = f"rbac-builder-{body.commonName.replace(':', '-')}-{pysecrets.token_hex(4)}"
    try:
        with api_client_for(kc, settings, session.username) as api:
            result = ops.submit_and_approve_csr(
                api, settings, csr_name=csr_name, csr_pem=body.csrPem, ttl_seconds=ttl)
    except ops.K8sOperationError as exc:
        raise _handle(exc)

    from ruamel.yaml import YAML
    yaml = YAML(typ="safe", pure=True)
    stored = yaml.load(kc)
    ca_b64 = stored["clusters"][0]["cluster"].get("certificate-authority-data", "")
    expires = expiry_from_ttl(result["ttlSeconds"])
    audit.emit("kubeconfig.generate", cluster=cluster, target=body.commonName,
               credential="user-cert", ttl_seconds=result["ttlSeconds"],
               expires_at=expires.isoformat(timespec="seconds"),
               **_audit_ctx(request, session))
    return {
        "certificatePem": result["certificate"],
        "clusterDetails": {
            "clusterName": cluster,
            "serverUrl": md.publicApiUrl or md.serverUrl,
            "caDataB64": ca_b64,
            "defaultNamespace": body.defaultNamespace,
        },
        "expiresAt": expires.isoformat(timespec="seconds"),
        "filename": kubeconfig_filename(cluster, body.commonName, expires),
        "warning": "Kubernetes client certificates cannot be revoked; to cut "
                   "access remove the bindings",
    }
