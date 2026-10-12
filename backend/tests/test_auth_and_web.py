"""Auth and web hardening tests."""
import pytest

from app.settings import Settings, StartupError, validate_startup
from tests.conftest import TEST_PASSWORD, login, make_app


# -- startup invariants -------------------------------------------------------

def test_no_password_refuses_start():
    with pytest.raises(StartupError):
        validate_startup(Settings(_env_file=None, auth_mode="local"))


def test_auth_none_with_store_refuses():
    with pytest.raises(StartupError):
        validate_startup(Settings(_env_file=None, auth_mode="none", cluster_store="local",
                                  store_key_ref="env:X"))


def test_multi_worker_refuses():
    with pytest.raises(StartupError):
        validate_startup(Settings(_env_file=None, auth_mode="none", workers=4))


def test_off_loopback_http_refuses():
    with pytest.raises(StartupError):
        validate_startup(Settings(_env_file=None, auth_mode="none", public_url="http://rbac.corp.example"))
    # allowed with the explicit flag
    warnings = validate_startup(Settings(_env_file=None, auth_mode="none",
                                         public_url="http://rbac.corp.example",
                                         allow_insecure_http=True))
    assert warnings


def test_plaintext_env_password_hashed_and_dropped(tmp_path, monkeypatch):
    import os
    monkeypatch.setenv("RBAC_UI_ADMIN_PASSWORD", "a-sufficiently-long-pw-42")
    app, _ = make_app(tmp_path, admin_password_hash=None,
                      admin_password="a-sufficiently-long-pw-42")
    assert "RBAC_UI_ADMIN_PASSWORD" not in os.environ


# -- login / sessions ---------------------------------------------------------

def test_login_and_session_flow(client):
    # unauthenticated call is denied
    assert client.get("/api/config").status_code == 401
    data = login(client)
    assert data["role"] == "admin"
    assert client.get("/api/config").status_code == 200
    # logout invalidates server-side
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/config").status_code == 401


def test_generic_login_error(client):
    r1 = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    r2 = client.post("/api/auth/login", json={"username": "ghost", "password": "wrong"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()  # same generic message


def test_lockout_after_max_attempts(tmp_path):
    app, settings = make_app(tmp_path)
    from fastapi.testclient import TestClient
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        for _ in range(5):
            client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
        # 6th attempt: IP locked
        r = client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
        assert r.status_code == 429


def test_session_id_changes_at_login(client):
    login(client)
    sid1 = client.cookies.get("rbac_ui_session")
    client.post("/api/auth/logout")
    client.headers.pop("x-csrf-token", None)
    login(client)
    sid2 = client.cookies.get("rbac_ui_session")
    assert sid1 != sid2 and len(sid2) >= 43  # 256-bit urlsafe


def test_session_cookie_flags(client):
    resp = client.post("/api/auth/login",
                       json={"username": "admin", "password": TEST_PASSWORD})
    set_cookie = resp.headers["set-cookie"]
    assert "HttpOnly" in set_cookie and "SameSite=strict" in set_cookie.replace("Strict", "strict")
    assert "Path=/" in set_cookie


def test_password_rotation_revokes_sessions(tmp_path, monkeypatch):
    from app.auth import passwords
    monkeypatch.setenv("PW_REF", passwords.hash_password(TEST_PASSWORD))
    app, _ = make_app(tmp_path, admin_password_hash=None, admin_password_ref="env:PW_REF")
    from fastapi.testclient import TestClient
    from app.auth.service import get_auth_service
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        login(client)
        assert client.get("/api/config").status_code == 200
        auth = get_auth_service()
        # unchanged value: nothing revoked
        assert auth.check_rotation_once() is False
        assert client.get("/api/config").status_code == 200
        # changed value revokes
        monkeypatch.setenv("PW_REF", passwords.hash_password("new-password-abcdef-99"))
        assert auth.check_rotation_once() is True
        assert client.get("/api/config").status_code == 401


def test_secret_outage_revokes_nothing(tmp_path, monkeypatch):
    from app.auth import passwords
    monkeypatch.setenv("PW_REF2", passwords.hash_password(TEST_PASSWORD))
    app, _ = make_app(tmp_path, admin_password_hash=None, admin_password_ref="env:PW_REF2")
    from fastapi.testclient import TestClient
    from app.auth.service import get_auth_service
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        login(client)
        monkeypatch.delenv("PW_REF2")  # simulate backend outage
        assert get_auth_service().check_rotation_once() is False
        assert client.get("/api/config").status_code == 200


# -- web hardening ------------------------------------------------------------

def test_host_header_rejected(client):
    r = client.get("/healthz", headers={"Host": "evil.example"})
    assert r.status_code == 400  # DNS rebinding


def test_foreign_origin_rejected(client):
    login(client)
    r = client.post("/api/lint", json={"roles": [], "bindings": [], "serviceAccounts": []},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_post_without_csrf_rejected(client):
    login(client)
    client.headers.pop("x-csrf-token")
    r = client.post("/api/lint", json={"roles": [], "bindings": [], "serviceAccounts": []})
    assert r.status_code == 403  # synchronizer token


def test_security_headers_present(client):
    r = client.get("/healthz")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"
    assert "Access-Control-Allow-Origin" not in r.headers  # CORS disabled


def test_healthz_leaks_nothing(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_body_limit(client):
    login(client)
    r = client.post("/api/lint", content=b"x" * (2 * 1024 * 1024),
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413


# -- route inventory ---------------------------------------------------------

def test_route_inventory(tmp_path):
    """Every API route declares a permission or is on the public allowlist."""
    app, _ = make_app(tmp_path)
    from app.routers import auth_routes, builder_routes, cluster_routes, k8s_routes
    public = {"/api/auth/login", "/healthz"}
    unprotected = []
    for router in (auth_routes.router, builder_routes.router,
                   cluster_routes.router, k8s_routes.router):
        for route in router.routes:
            if route.path in public:
                continue
            has_permission = any(
                getattr(dep.call, "required_permission", None)
                for dep in route.dependant.dependencies
            )
            if not has_permission:
                unprotected.append(route.path)
    assert not unprotected, f"routes without a permission declaration: {unprotected}"


def test_offline_mode_needs_no_login(offline_client):
    r = offline_client.get("/api/config")
    assert r.status_code == 200
    assert r.json()["authMode"] == "none"
