"""Cluster operations: discovery, RBAC read, dry-run/apply, SAR,
identity inspection, TokenRequest, CSR flow."""
from __future__ import annotations

import base64
import functools
import json
import time
from datetime import datetime, timezone
from typing import Any

from kubernetes import client as k8s
from kubernetes.client.rest import ApiException
from urllib3.exceptions import HTTPError as TransportError

from ..settings import Settings

FIELD_MANAGER = "k8s-rbac-builder"
RBAC_API_VERSION = "rbac.authorization.k8s.io/v1"


class K8sOperationError(RuntimeError):
    """Redacted, client-safe Kubernetes error."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def _redact_api_exception(exc: ApiException) -> K8sOperationError:
    reason = exc.reason or "Kubernetes API error"
    detail = ""
    try:
        body = json.loads(exc.body or "{}")
        detail = body.get("message", "")
    except (ValueError, TypeError):
        pass
    # Pass through the API server's message after dropping header/auth context.
    msg = f"{reason}: {detail}" if detail else reason
    return K8sOperationError(msg[:500], status=exc.status or 502)


def _client_safe(fn):
    """Transport failures (timeout, refused, DNS, TLS) and stray ApiExceptions
    become redacted K8sOperationErrors instead of unhandled 500s."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except K8sOperationError:
            raise
        except ApiException as exc:
            raise _redact_api_exception(exc) from exc
        except (TransportError, OSError) as exc:
            raise K8sOperationError(
                "cannot reach the cluster API server — connection timed out or "
                "was refused; check the server URL and network reachability",
                status=502) from exc
    return wrapper


def _timeout(settings: Settings) -> int:
    return settings.k8s_timeout_s


def _raw_call(api: k8s.ApiClient, settings: Settings, path: str, method: str = "GET",
              *, body: dict | None = None, header_params: dict | None = None,
              query_params: list | None = None):
    """Raw API call compatible with kubernetes-client >= 25 (response_types_map)."""
    return api.call_api(
        path, method, body=body, header_params=header_params,
        query_params=query_params,
        # v36 keys this map by int status; older generators used str keys.
        response_types_map={200: "object", 201: "object", 202: "object",
                            "200": "object", "201": "object", "202": "object"},
        auth_settings=["BearerToken"], _return_http_data_only=True,
        _request_timeout=_timeout(settings),
    )


# -- discovery ----------------------------------------------------------------

@_client_safe
def server_version(api: k8s.ApiClient, settings: Settings) -> dict:
    data = _raw_call(api, settings, "/version")
    minor = "".join(ch for ch in data.get("minor", "") if ch.isdigit())
    return {"gitVersion": data.get("gitVersion", ""),
            "minor": f"{data.get('major', '1')}.{minor}"}


@_client_safe
def discover(api: k8s.ApiClient, settings: Settings) -> dict:
    """Namespaces, API groups/resources (incl. CRDs and subresources), SAs, roles."""
    t = _timeout(settings)
    core = k8s.CoreV1Api(api)
    rbac = k8s.RbacAuthorizationV1Api(api)

    try:
        namespaces = [ns.metadata.name for ns in
                      core.list_namespace(_request_timeout=t).items]
        groups: list[dict] = []
        core_res = _raw_call(api, settings, "/api/v1")
        groups.append({
            "name": "", "displayName": "core",
            "resources": [{"name": r["name"], "verbs": r.get("verbs", [])}
                          for r in core_res.get("resources", [])],
        })
        group_list = _raw_call(api, settings, "/apis")
        for g in group_list.get("groups", []):
            gv = g["preferredVersion"]["groupVersion"]
            try:
                res = _raw_call(api, settings, f"/apis/{gv}")
            except ApiException:
                continue
            groups.append({
                "name": g["name"], "displayName": g["name"],
                "resources": [{"name": r["name"], "verbs": r.get("verbs", [])}
                              for r in res.get("resources", [])],
            })
        sas = core.list_service_account_for_all_namespaces(_request_timeout=t)
        service_accounts = [
            {"name": s.metadata.name, "namespace": s.metadata.namespace} for s in sas.items
        ]
        cluster_roles = [r.metadata.name for r in
                         rbac.list_cluster_role(_request_timeout=t).items]
        roles = [{"name": r.metadata.name, "namespace": r.metadata.namespace}
                 for r in rbac.list_role_for_all_namespaces(_request_timeout=t).items]
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc

    return {
        "namespaces": sorted(namespaces),
        "groups": groups,
        "serviceAccounts": service_accounts,
        "clusterRoles": sorted(cluster_roles),
        "roles": roles,
        "version": server_version(api, settings),
    }


# -- identity -----------------------------------------------------------------

@_client_safe
def inspect_identity(api: k8s.ApiClient, settings: Settings) -> dict:
    t = _timeout(settings)
    username, groups = "", []
    try:
        # SelfSubjectReview GA in 1.28; fall back to SSAR-only info.
        body = {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}
        resp = _raw_call(api, settings,
                         "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                         "POST", body=body)
        info = resp.get("status", {}).get("userInfo", {})
        username = info.get("username", "")
        groups = info.get("groups", []) or []
    except ApiException:
        pass

    auth = k8s.AuthorizationV1Api(api)
    def can(verb: str, resource: str, group: str = "") -> bool:
        try:
            r = auth.create_self_subject_access_review(
                k8s.V1SelfSubjectAccessReview(spec=k8s.V1SelfSubjectAccessReviewSpec(
                    resource_attributes=k8s.V1ResourceAttributes(
                        verb=verb, resource=resource, group=group))),
                _request_timeout=t)
            return bool(r.status.allowed)
        except ApiException:
            return False

    is_cluster_admin = can("*", "*")
    return {
        "username": username,
        "groups": groups,
        "isClusterAdmin": is_cluster_admin,
        "isSystemMasters": "system:masters" in groups,
    }


# -- RBAC objects -------------------------------------------------------------

_KIND_API = {
    "Role": ("list_role_for_all_namespaces", "roles"),
    "ClusterRole": ("list_cluster_role", "clusterroles"),
    "RoleBinding": ("list_role_binding_for_all_namespaces", "rolebindings"),
    "ClusterRoleBinding": ("list_cluster_role_binding", "clusterrolebindings"),
}


@_client_safe
def list_rbac_objects(api: k8s.ApiClient, settings: Settings) -> dict[str, list[dict]]:
    rbac = k8s.RbacAuthorizationV1Api(api)
    t = _timeout(settings)
    out: dict[str, list[dict]] = {}
    try:
        for kind, (method, key) in _KIND_API.items():
            items = getattr(rbac, method)(_request_timeout=t).items
            serialized = []
            for item in items:
                d = api.sanitize_for_serialization(item)
                # The API server omits apiVersion/kind on items inside a List,
                # but the linter dispatches on kind — put them back.
                d["apiVersion"] = RBAC_API_VERSION
                d["kind"] = kind
                serialized.append(d)
            out[key] = serialized
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc
    return out


@_client_safe
def get_rbac_object(api: k8s.ApiClient, settings: Settings, kind: str,
                    name: str, namespace: str | None) -> dict:
    rbac = k8s.RbacAuthorizationV1Api(api)
    t = _timeout(settings)
    try:
        if kind == "Role":
            obj = rbac.read_namespaced_role(name, namespace, _request_timeout=t)
        elif kind == "RoleBinding":
            obj = rbac.read_namespaced_role_binding(name, namespace, _request_timeout=t)
        elif kind == "ClusterRole":
            obj = rbac.read_cluster_role(name, _request_timeout=t)
        elif kind == "ClusterRoleBinding":
            obj = rbac.read_cluster_role_binding(name, _request_timeout=t)
        else:
            raise K8sOperationError(f"unsupported kind {kind}", status=400)
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc
    return api.sanitize_for_serialization(obj)


# -- apply / dry-run ----------------------------------------------------------

_APPLY_PATHS = {
    ("Role", True): "/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{name}",
    ("RoleBinding", True): "/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}",
    ("ClusterRole", False): "/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}",
    ("ClusterRoleBinding", False): "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}",
    ("ServiceAccount", True): "/api/v1/namespaces/{ns}/serviceaccounts/{name}",
}


@_client_safe
def server_side_apply(api: k8s.ApiClient, settings: Settings, manifest: dict,
                      *, dry_run: bool, app_user: str) -> dict:
    kind = manifest.get("kind")
    md = manifest.get("metadata", {})
    name, ns = md.get("name"), md.get("namespace")
    namespaced = kind in ("Role", "RoleBinding", "ServiceAccount")
    key = (kind, namespaced)
    if key not in _APPLY_PATHS:
        raise K8sOperationError(f"unsupported kind {kind}", status=400)
    path = _APPLY_PATHS[key].format(ns=ns, name=name)

    # Attribution annotations on real applies.
    if not dry_run:
        annotations = manifest.setdefault("metadata", {}).setdefault("annotations", {})
        annotations.setdefault("rbac-builder/applied-by", app_user)
        annotations.setdefault("rbac-builder/applied-at",
                               datetime.now(timezone.utc).isoformat(timespec="seconds"))

    params = [("fieldManager", FIELD_MANAGER), ("force", "true")]
    if dry_run:
        params.append(("dryRun", "All"))
    try:
        resp = _raw_call(
            api, settings, path, "PATCH", body=manifest,
            header_params={"Content-Type": "application/apply-patch+yaml"},
            query_params=params,
        )
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc
    return resp


@_client_safe
def delete_object(api: k8s.ApiClient, settings: Settings, kind: str,
                  name: str, namespace: str | None) -> None:
    rbac = k8s.RbacAuthorizationV1Api(api)
    core = k8s.CoreV1Api(api)
    t = _timeout(settings)
    try:
        if kind == "Role":
            rbac.delete_namespaced_role(name, namespace, _request_timeout=t)
        elif kind == "RoleBinding":
            rbac.delete_namespaced_role_binding(name, namespace, _request_timeout=t)
        elif kind == "ClusterRole":
            rbac.delete_cluster_role(name, _request_timeout=t)
        elif kind == "ClusterRoleBinding":
            rbac.delete_cluster_role_binding(name, _request_timeout=t)
        elif kind == "ServiceAccount":
            core.delete_namespaced_service_account(name, namespace, _request_timeout=t)
        else:
            raise K8sOperationError(f"unsupported kind {kind}", status=400)
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc


# -- SAR / can-i --------------------------------------------------------------

@_client_safe
def subject_access_review(api: k8s.ApiClient, settings: Settings, *,
                          user: str | None, groups: list[str],
                          verb: str, resource: str, group: str,
                          namespace: str | None, name: str | None) -> dict:
    auth = k8s.AuthorizationV1Api(api)
    spec = k8s.V1SubjectAccessReviewSpec(
        user=user, groups=groups or None,
        resource_attributes=k8s.V1ResourceAttributes(
            verb=verb, resource=resource, group=group or None,
            namespace=namespace, name=name,
        ),
    )
    try:
        resp = auth.create_subject_access_review(
            k8s.V1SubjectAccessReview(spec=spec), _request_timeout=_timeout(settings))
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc
    return {"allowed": bool(resp.status.allowed),
            "reason": resp.status.reason or "",
            "denied": bool(getattr(resp.status, "denied", False))}


@_client_safe
def self_can(api: k8s.ApiClient, settings: Settings, *, verb: str, resource: str,
             group: str = "", namespace: str | None = None, name: str | None = None) -> bool:
    auth = k8s.AuthorizationV1Api(api)
    try:
        r = auth.create_self_subject_access_review(
            k8s.V1SelfSubjectAccessReview(spec=k8s.V1SelfSubjectAccessReviewSpec(
                resource_attributes=k8s.V1ResourceAttributes(
                    verb=verb, resource=resource, group=group or None,
                    namespace=namespace, name=name))),
            _request_timeout=_timeout(settings))
        return bool(r.status.allowed)
    except ApiException:
        return False


# -- tokens -------------------------------------------------------------------

@_client_safe
def create_sa_token(api: k8s.ApiClient, settings: Settings, *, namespace: str,
                    service_account: str, ttl_seconds: int) -> dict:
    ttl = min(ttl_seconds, settings.max_token_ttl_s)  # clamp to the cap
    core = k8s.CoreV1Api(api)
    try:
        resp = core.create_namespaced_service_account_token(
            service_account, namespace,
            k8s.AuthenticationV1TokenRequest(
                spec=k8s.V1TokenRequestSpec(audiences=None, expiration_seconds=ttl)),
            _request_timeout=_timeout(settings))
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc
    return {"token": resp.status.token,
            "expirationTimestamp": resp.status.expiration_timestamp.isoformat()
            if resp.status.expiration_timestamp else None,
            "ttlSeconds": ttl}


# -- CSR flow -----------------------------------------------------------------

@_client_safe
def submit_and_approve_csr(api: k8s.ApiClient, settings: Settings, *,
                           csr_name: str, csr_pem: str, ttl_seconds: int,
                           wait_seconds: int = 20) -> dict:
    ttl = min(ttl_seconds, settings.max_cert_ttl_s)
    certs = k8s.CertificatesV1Api(api)
    body = k8s.V1CertificateSigningRequest(
        metadata=k8s.V1ObjectMeta(name=csr_name),
        spec=k8s.V1CertificateSigningRequestSpec(
            request=base64.b64encode(csr_pem.encode()).decode(),
            signer_name="kubernetes.io/kube-apiserver-client",
            expiration_seconds=ttl,
            usages=["client auth"],
        ),
    )
    t = _timeout(settings)
    try:
        certs.create_certificate_signing_request(body, _request_timeout=t)
        csr = certs.read_certificate_signing_request(csr_name, _request_timeout=t)
        csr.status.conditions = [k8s.V1CertificateSigningRequestCondition(
            type="Approved", status="True", reason="RBACBuilderApproval",
            message="approved by RBACGrant")]
        certs.replace_certificate_signing_request_approval(csr_name, csr, _request_timeout=t)
        deadline = time.monotonic() + wait_seconds
        cert_b64 = None
        while time.monotonic() < deadline:
            got = certs.read_certificate_signing_request(csr_name, _request_timeout=t)
            if got.status and got.status.certificate:
                cert_b64 = got.status.certificate
                break
            time.sleep(0.5)
        if not cert_b64:
            raise K8sOperationError(
                "the CSR was approved but the certificate was not issued in time; "
                "fetch it later with kubectl get csr", status=504)
        certs.delete_certificate_signing_request(csr_name, _request_timeout=t)
    except ApiException as exc:
        raise _redact_api_exception(exc) from exc
    return {"certificate": base64.b64decode(cert_b64).decode(), "ttlSeconds": ttl}
