"""RBACGrant server: FastAPI app factory, startup checks and static
frontend serving. Binds to 127.0.0.1 by default."""
from __future__ import annotations

import logging
import resource
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth.service import AuthService, set_auth_service
from .k8s.client_factory import wipe_runtime_dir
from .routers import auth_routes, builder_routes, cluster_routes, k8s_routes
from .secrets.provider import SecretProvider, set_secret_provider
from .security.audit import init_audit
from .security.middleware import SecurityMiddleware
from .security.redaction import install_redaction
from .settings import Settings, StartupError, get_settings, set_settings, validate_startup
from .state import runtime_state
from .store.registry import ClusterRegistry, set_registry

log = logging.getLogger("rbac_ui")

FRONTEND_DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"


def _disable_core_dumps() -> None:
    """Secrets must not leak through crash dumps."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
    if sys.platform == "linux":
        try:
            import ctypes
            ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 4
        except Exception:  # noqa: BLE001
            pass


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is not None:
        set_settings(settings)
    settings = get_settings()

    logging.basicConfig(level=settings.log_level.upper())
    install_redaction()
    _disable_core_dumps()

    warnings = validate_startup(settings)  # raises StartupError on refusal
    for w in warnings:
        log.warning(w)

    audit = init_audit(settings.audit_log_file, settings.audit_log_max_size_bytes)
    runtime_state.read_only = settings.read_only

    secret_provider = SecretProvider(settings)
    set_secret_provider(secret_provider)

    # Every configured ref must resolve, or fail fast naming the ref.
    for ref in filter(None, [settings.admin_password_ref, settings.users_ref,
                             settings.store_key_ref]):
        if not ref.startswith("vault-transit:"):
            secret_provider.check(ref)

    auth = AuthService(settings, secret_provider)
    set_auth_service(auth)

    registry = ClusterRegistry(settings, secret_provider)
    set_registry(registry)

    wipe_runtime_dir(settings)  # wiped on startup

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        auth.start_rotation_watch()
        audit.emit("server.start", result="ok")
        yield
        auth.stop_rotation_watch()
        wipe_runtime_dir(settings)  # wiped on shutdown
        audit.emit("server.stop", result="ok")
        audit.close()

    app = FastAPI(title="RBACGrant", version="0.1.0",
                  lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    # CORS stays disabled: no Access-Control-Allow-* headers anywhere.
    app.add_middleware(SecurityMiddleware, settings=settings)

    app.include_router(auth_routes.router)
    app.include_router(builder_routes.router)
    app.include_router(cluster_routes.router)
    app.include_router(k8s_routes.router)

    @app.get("/healthz")
    async def healthz() -> dict:
        # Liveness only; backend detail is on the authed /api/status.
        return {"status": "ok"}

    if FRONTEND_DIST.is_dir():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str):
            # An unknown /api/* path is a missing endpoint (often a stale
            # server), never a SPA route — answer JSON, not index.html.
            if path.startswith("api/") or path == "api":
                return JSONResponse({"detail": f"no such API endpoint: /{path} "
                                     "(is the server up to date? restart it)"}, 404)
            candidate = (FRONTEND_DIST / path).resolve()
            if (path and candidate.is_file()
                    and candidate.is_relative_to(FRONTEND_DIST.resolve())):
                return FileResponse(candidate)
            return FileResponse(FRONTEND_DIST / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        async def no_frontend() -> JSONResponse:
            return JSONResponse({"detail": "frontend not built; run make frontend"}, 503)

    return app


def run() -> None:
    import uvicorn
    try:
        settings = get_settings()
        app = create_app(settings)
    except StartupError as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(1)
    kwargs: dict = {}
    if settings.tls_cert_file and settings.tls_key_file:
        kwargs.update(ssl_certfile=settings.tls_cert_file, ssl_keyfile=settings.tls_key_file)
    uvicorn.run(app, host=settings.bind_addr, port=settings.port,
                log_level=settings.log_level, **kwargs)


if __name__ == "__main__":
    run()
