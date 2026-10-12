"""Web hardening middleware: Host allowlist (DNS rebinding), Origin/CSRF
checks, security headers, no-store on API responses, body size limits."""
from __future__ import annotations

import secrets
import uuid
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..settings import Settings

# 'unsafe-inline' applies to styles only: Mantine and Monaco inject runtime
# <style> elements. script-src stays strict 'self' (no inline scripts, no CDN).
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "worker-src 'self' blob:; img-src 'self' data:; connect-src 'self'; "
    "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "x-csrf-token"

# Public paths: everything else needs a session.
PUBLIC_PATHS = {"/api/auth/login", "/healthz"}
DEFAULT_BODY_LIMIT = 1 * 1024 * 1024        # 1 MiB
KUBECONFIG_BODY_LIMIT = 256 * 1024          # 256 KiB


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings
        self.allowed_hosts = set(settings.allowed_hosts_list)
        pub = urlparse(settings.public_url)
        self.public_origin = f"{pub.scheme}://{pub.netloc}".lower()

    async def dispatch(self, request: Request, call_next) -> Response:
        request.state.request_id = uuid.uuid4().hex[:16]

        # DNS rebinding: Host must be allowlisted.
        host = (request.headers.get("host") or "").split(":")[0].strip().lower()
        if host not in self.allowed_hosts:
            return self._plain_error(400, "invalid Host header")

        # Request body limits.
        length = request.headers.get("content-length")
        limit = (
            KUBECONFIG_BODY_LIMIT
            if request.url.path.startswith("/api/clusters") and "kubeconfig" in request.url.path
            else DEFAULT_BODY_LIMIT
        )
        if length is not None and length.isdigit() and int(length) > limit:
            return self._plain_error(413, "request body too large")

        # Origin/Referer check on state-changing requests.
        if request.method not in SAFE_METHODS and request.url.path.startswith("/api"):
            origin = request.headers.get("origin") or request.headers.get("referer")
            if origin:
                parsed = urlparse(origin)
                got = f"{parsed.scheme}://{parsed.netloc}".lower()
                if got != self.public_origin:
                    return self._plain_error(403, "cross-origin request rejected")

        response = await call_next(request)

        # Security headers on every response.
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        if self.settings.public_url_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        # No-store on API responses and credential downloads.
        if request.url.path.startswith("/api") or request.url.path == "/healthz":
            response.headers["Cache-Control"] = "no-store"
        return response

    @staticmethod
    def _plain_error(status: int, detail: str) -> JSONResponse:
        resp = JSONResponse({"detail": detail}, status_code=status)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp


def session_cookie_name(settings: Settings) -> str:
    # __Host- prefix requires Secure + Path=/ + no Domain.
    return "__Host-rbac_ui_session" if settings.public_url_https else "rbac_ui_session"


def set_session_cookie(response: Response, settings: Settings, session_id: str) -> None:
    response.set_cookie(
        session_cookie_name(settings),
        session_id,
        httponly=True,
        samesite="strict",
        secure=settings.public_url_https,
        path="/",
        max_age=settings.session_max_age_s,
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(session_cookie_name(settings), path="/")


def csrf_ok(request: Request, expected_token: str) -> bool:
    """Synchronizer token on every state-changing request."""
    if request.method in SAFE_METHODS:
        return True
    supplied = request.headers.get(CSRF_HEADER, "")
    return bool(supplied) and secrets.compare_digest(supplied, expected_token)
