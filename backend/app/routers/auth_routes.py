"""Login, logout, step-up and session info."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..auth.service import get_auth_service
from ..security.audit import get_audit
from ..security.deps import get_client_ip, require
from ..security.middleware import clear_session_cookie, set_session_cookie, session_cookie_name
from ..settings import get_settings

router = APIRouter(prefix="/api/auth", tags=["auth"])

GENERIC_LOGIN_ERROR = "invalid username or password"  # always the same


class LoginBody(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=1024)


@router.post("/login")
async def login(body: LoginBody, request: Request) -> JSONResponse:
    settings = get_settings()
    if settings.auth_mode == "none":
        raise HTTPException(status_code=404, detail="authentication is disabled")
    auth = get_auth_service()
    audit = get_audit()
    ip = get_client_ip(request)

    allowed, delay = auth.limiter.check(body.username, ip)
    if not allowed:
        audit.emit("login.lockout", user=body.username, source_ip=ip,
                   request_id=request.state.request_id, result="locked")
        raise HTTPException(status_code=429, detail=GENERIC_LOGIN_ERROR)
    if delay:
        await asyncio.sleep(delay)

    user = auth.authenticate(body.username, body.password)
    if user is None:
        auth.limiter.record_failure(body.username, ip)
        audit.emit("login.failure", user=body.username, source_ip=ip,
                   request_id=request.state.request_id, result="denied")
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    auth.limiter.record_success(body.username, ip)
    session = auth.sessions.create(user.username, user.role, user.clusters)
    audit.emit("login.success", user=user.username, source_ip=ip,
               request_id=request.state.request_id)
    resp = JSONResponse({
        "username": user.username, "role": user.role, "csrfToken": session.csrf_token,
    })
    set_session_cookie(resp, settings, session.session_id)
    return resp


@router.post("/logout")
async def logout(request: Request, session=require("builder:use")) -> JSONResponse:
    settings = get_settings()
    auth = get_auth_service()
    sid = request.cookies.get(session_cookie_name(settings))
    if sid:
        auth.sessions.invalidate(sid)
    get_audit().emit("logout", user=session.username, source_ip=get_client_ip(request),
                     request_id=request.state.request_id)
    resp = JSONResponse({"ok": True})
    clear_session_cookie(resp, settings)
    return resp


class StepUpBody(BaseModel):
    password: str = Field(max_length=1024)


@router.post("/step-up")
async def step_up(body: StepUpBody, request: Request,
                  session=require("builder:use")) -> dict:
    """Re-enter the password to unlock dangerous actions for a window."""
    auth = get_auth_service()
    audit = get_audit()
    ip = get_client_ip(request)
    allowed, delay = auth.limiter.check(session.username, ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=GENERIC_LOGIN_ERROR)
    if delay:
        await asyncio.sleep(delay)
    if not auth.verify_current_password(session.username, body.password):
        auth.limiter.record_failure(session.username, ip)
        audit.emit("step_up", user=session.username, source_ip=ip,
                   request_id=request.state.request_id, result="denied")
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
    auth.limiter.record_success(session.username, ip)
    # look up the real stored session (require() returns it attached)
    sid = request.cookies.get(session_cookie_name(get_settings()))
    if sid:
        auth.sessions.mark_step_up(sid)
    audit.emit("step_up", user=session.username, source_ip=ip,
               request_id=request.state.request_id)
    return {"ok": True, "windowSeconds": get_settings().step_up_window_s}


@router.get("/me")
async def me(request: Request, session=require("builder:use")) -> dict:
    settings = get_settings()
    auth = get_auth_service()
    fresh = (settings.auth_mode == "none"
             or auth.sessions.has_fresh_step_up(session, settings.step_up_window_s))
    return {
        "username": session.username,
        "role": session.role,
        "csrfToken": session.csrf_token,
        "stepUpFresh": fresh,
        "authMode": settings.auth_mode,
    }
