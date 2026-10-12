"""Offline builder routes: preview, lint, export,
catalog, profiles and starter templates."""
from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import catalog as catalog_pkg
from ..generators import exporters
from ..generators.manifests import bundle_manifests, to_yaml
from ..linter import evaluate_guardrails, lint_bundle
from ..linter.rules import least_privilege_score
from ..models.rbac import Bundle
from ..security.deps import require
from ..settings import get_settings
from ..state import runtime_state

router = APIRouter(prefix="/api", tags=["builder"])

PROFILE_SCHEMA_VERSION = 1
# The save path rejects credential material with a secret scan.
_SECRET_SCAN = [
    re.compile(r"-----BEGIN"),
    re.compile(r"client-key-data"),
    re.compile(r"client-certificate-data"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\."),          # JWTs
    re.compile(r"(?i)\bkind:\s*Config\b"),           # embedded kubeconfigs
    re.compile(r"\bhvs\.[A-Za-z0-9_-]{20,}"),
]
_PROFILE_NAME = re.compile(r"^[a-z0-9]([-a-z0-9_]{0,61}[a-z0-9])?$")


class PreviewResponse(BaseModel):
    yaml: str
    findings: list[dict]
    score: int


@router.post("/preview")
async def preview(bundle: Bundle, session=require("builder:use")) -> PreviewResponse:
    findings = lint_bundle(bundle)
    return PreviewResponse(
        yaml=to_yaml(bundle_manifests(bundle)),
        findings=[f.model_dump() for f in findings],
        score=least_privilege_score(findings),
    )


@router.post("/lint")
async def lint(bundle: Bundle, session=require("lint:run")) -> dict:
    findings = lint_bundle(bundle)
    return {"findings": [f.model_dump() for f in findings],
            "score": least_privilege_score(findings)}


@router.post("/guardrails")
async def guardrails(bundle: Bundle, session=require("lint:run")) -> dict:
    decision = evaluate_guardrails(bundle_manifests(bundle))
    return decision.model_dump()


@router.post("/export/{fmt}")
async def export(fmt: str, bundle: Bundle, session=require("export:run")) -> Response:
    if fmt == "yaml":
        return Response(exporters.export_yaml(bundle), media_type="application/yaml")
    if fmt == "zip":
        return Response(exporters.export_zip(bundle), media_type="application/zip",
                        headers={"Content-Disposition": "attachment; filename=rbac-bundle.zip"})
    if fmt == "kubectl":
        return Response(exporters.export_kubectl(bundle), media_type="text/plain")
    if fmt == "kustomize":
        return Response(exporters.export_kustomization(bundle), media_type="application/yaml")
    raise HTTPException(status_code=404, detail="unknown export format")


@router.post("/import-yaml")
async def import_yaml(request: Request, session=require("builder:use")) -> dict:
    """Parse pasted/uploaded YAML with the safe loader into form state."""
    raw = await request.body()
    if len(raw) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="YAML too large")
    from ruamel.yaml import YAML
    yaml = YAML(typ="safe", pure=True)
    try:
        docs = [d for d in yaml.load_all(raw.decode("utf-8")) if isinstance(d, dict)]
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail="the YAML could not be parsed") from exc
    supported = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"}
    objects = [d for d in docs if d.get("kind") in supported]
    if not objects:
        raise HTTPException(status_code=422, detail="no RBAC objects found in the YAML")
    # Server-managed fields are dropped.
    for obj in objects:
        md = obj.get("metadata", {})
        for f in ("managedFields", "resourceVersion", "uid", "creationTimestamp",
                  "generation", "selfLink"):
            md.pop(f, None)
    return {"objects": objects}


# -- catalog ------------------------------------------------------------------

@router.get("/catalog")
async def catalog_index(session=require("builder:use")) -> dict:
    return {"minors": catalog_pkg.supported_minors()}


@router.get("/catalog/{minor}")
async def catalog_for(minor: str, session=require("builder:use")) -> dict:
    try:
        return catalog_pkg.load_catalog(minor)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# -- profiles -----------------------------------------------------------------

def _profiles_dir() -> Path:
    d = Path(get_settings().profiles_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


class ProfileBody(BaseModel):
    name: str = Field(max_length=64)
    bundle: Bundle
    variables: dict[str, str] = Field(default_factory=dict)


@router.get("/profiles")
async def list_profiles(session=require("builder:use")) -> dict:
    out = []
    for f in sorted(_profiles_dir().glob("*.json")):
        try:
            data = json.loads(f.read_text())
            out.append({"name": f.stem, "version": data.get("version"),
                        "savedAt": data.get("savedAt")})
        except (ValueError, OSError):
            continue
    return {"profiles": out}


@router.get("/profiles/{name}")
async def get_profile(name: str, session=require("builder:use")) -> dict:
    if not _PROFILE_NAME.match(name):
        raise HTTPException(status_code=400, detail="invalid profile name")
    path = _profiles_dir() / f"{name}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="profile not found")
    data = json.loads(path.read_text())
    version = data.get("version", 0)
    if version > PROFILE_SCHEMA_VERSION:
        raise HTTPException(
            status_code=409,
            detail=f"profile schema version {version} is newer than this app "
                   f"supports ({PROFILE_SCHEMA_VERSION}); upgrade the app")
    return data


@router.put("/profiles/{name}")
async def save_profile(name: str, body: ProfileBody, session=require("builder:use")) -> dict:
    if not _PROFILE_NAME.match(name):
        raise HTTPException(status_code=400, detail="invalid profile name")
    serialized = body.model_dump_json()
    for pattern in _SECRET_SCAN:
        if pattern.search(serialized):
            raise HTTPException(
                status_code=422,
                detail="the profile contains credential-like content and was not saved")
    from datetime import datetime, timezone
    data = {
        "version": PROFILE_SCHEMA_VERSION,
        "name": name,
        "savedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "bundle": json.loads(body.bundle.model_dump_json()),
        "variables": body.variables,
    }
    (_profiles_dir() / f"{name}.json").write_text(json.dumps(data, indent=2))
    return {"ok": True, "name": name}


@router.delete("/profiles/{name}")
async def delete_profile(name: str, session=require("builder:use")) -> dict:
    if not _PROFILE_NAME.match(name):
        raise HTTPException(status_code=400, detail="invalid profile name")
    path = _profiles_dir() / f"{name}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="profile not found")
    path.unlink()
    return {"ok": True}


# -- templates ----------------------------------------------------------------

@router.get("/templates")
async def list_templates(session=require("builder:use")) -> dict:
    templates_dir = Path(__file__).parent.parent / "templates"
    out = []
    for f in sorted(templates_dir.glob("*.json")):
        data = json.loads(f.read_text())
        out.append({"id": f.stem, "title": data.get("title", f.stem),
                    "description": data.get("description", "")})
    return {"templates": out}


@router.get("/templates/{template_id}")
async def get_template(template_id: str, session=require("builder:use")) -> dict:
    if not _PROFILE_NAME.match(template_id):
        raise HTTPException(status_code=400, detail="invalid template id")
    path = Path(__file__).parent.parent / "templates" / f"{template_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="template not found")
    return json.loads(path.read_text())


# -- misc ---------------------------------------------------------------------

@router.get("/config")
async def app_config(session=require("builder:use")) -> dict:
    s = get_settings()
    return {
        "brandName": s.brand_name,
        "clusterStore": s.cluster_store,
        "readOnly": runtime_state.read_only,
        "authMode": s.auth_mode,
        "maxTokenTtlSeconds": s.max_token_ttl_s,
        "defaultTokenTtlSeconds": s.default_token_ttl_s,
        "maxCertTtlSeconds": s.max_cert_ttl_s,
        "defaultCertTtlSeconds": s.default_cert_ttl_s,
        "allowLegacySaTokens": s.allow_legacy_sa_tokens,
    }


class ReadOnlyBody(BaseModel):
    readOnly: bool


@router.post("/read-only")
async def toggle_read_only(body: ReadOnlyBody, request: Request,
                           session=require("readonly:toggle")) -> dict:
    from ..security.audit import get_audit
    from ..security.deps import get_client_ip
    runtime_state.read_only = body.readOnly
    get_audit().emit("read_only.toggle", user=session.username,
                     source_ip=get_client_ip(request),
                     request_id=request.state.request_id,
                     target=str(body.readOnly))
    return {"readOnly": runtime_state.read_only}


@router.get("/status")
async def status(session=require("status:view")) -> dict:
    """Backend reachability is authenticated-only (admin)."""
    s = get_settings()
    secret_backend = "unconfigured"
    if s.admin_password_ref:
        from ..secrets.provider import get_secret_provider, SecretRefError
        try:
            get_secret_provider().get(s.admin_password_ref, use_cache=False)
            secret_backend = "ok"
        except SecretRefError:
            secret_backend = "unreachable"
    return {"secretBackend": secret_backend, "clusterStore": s.cluster_store,
            "readOnly": runtime_state.read_only}
