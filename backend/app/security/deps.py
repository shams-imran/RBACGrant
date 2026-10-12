"""Route-level authorization: every API route declares the permission
it needs through one dependency; there are no ad-hoc checks inside handlers.

A route inventory test asserts every route carries a permission marker or
is on the explicit public allowlist.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from ..auth.service import get_auth_service, role_has
from ..auth.sessions import Session
from ..settings import get_settings
from .middleware import csrf_ok, session_cookie_name


def get_client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trusted_proxies and request.client:
        # Only trust X-Forwarded-For when the peer is a trusted proxy.
        import ipaddress
        peer = request.client.host
        for cidr in settings.trusted_proxies.split(","):
            try:
                if ipaddress.ip_address(peer) in ipaddress.ip_network(cidr.strip()):
                    fwd = request.headers.get("x-forwarded-for")
                    if fwd:
                        return fwd.split(",")[0].strip()
            except ValueError:
                continue
    return request.client.host if request.client else "unknown"


def _current_session(request: Request) -> Session:
    settings = get_settings()
    if settings.auth_mode == "none":
        # Personal profile: implicit local admin (loopback only, no store —).
        auth = get_auth_service()
        session = getattr(request.state, "_anon_session", None)
        if session is None:
            session = Session("anonymous", "local", "admin", 0, 0)
            request.state._anon_session = session
        return session
    auth = get_auth_service()
    sid = request.cookies.get(session_cookie_name(settings))
    if not sid:
        raise HTTPException(status_code=401, detail="authentication required")
    session = auth.sessions.get(sid)
    if session is None:
        raise HTTPException(status_code=401, detail="session expired or invalid")
    if not csrf_ok(request, session.csrf_token):
        raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
    return session


def require(permission: str):
    """Dependency factory: authenticates the session and checks the app role."""

    def dependency(request: Request) -> Session:
        session = _current_session(request)
        if not role_has(session.role, permission):
            raise HTTPException(status_code=403, detail="insufficient role")
        return session

    dependency.required_permission = permission  # route inventory marker
    return Depends(dependency)


def require_step_up(request: Request, session: Session) -> None:
    """The caller must have re-entered the password recently."""
    settings = get_settings()
    if settings.auth_mode == "none":
        return
    auth = get_auth_service()
    if not auth.sessions.has_fresh_step_up(session, settings.step_up_window_s):
        raise HTTPException(
            status_code=403,
            detail="step-up required: re-enter your password to confirm this action",
            headers={"X-Step-Up-Required": "true"},
        )


def require_writable() -> None:
    """Global read-only mode blocks every cluster write."""
    from ..state import runtime_state
    if runtime_state.read_only:
        raise HTTPException(status_code=403, detail="the server is in read-only mode")
