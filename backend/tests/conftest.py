from __future__ import annotations

import base64
import os
import secrets

import pytest
from fastapi.testclient import TestClient

from app.auth import passwords
from app.settings import Settings, set_settings
from app.secrets.provider import set_secret_provider
from app.auth.service import set_auth_service
from app.store.registry import set_registry

TEST_PASSWORD = "canary-Adm1n-passw0rd-2026"
TEST_PASSWORD_HASH = passwords.hash_password(TEST_PASSWORD)


def make_app(tmp_path, **overrides):
    """Build a fresh app instance with isolated dirs and clean singletons."""
    defaults = dict(
        auth_mode="local",
        admin_password_hash=TEST_PASSWORD_HASH,
        cluster_store="none",
        data_dir=str(tmp_path / "data"),
        runtime_dir=str(tmp_path / "runtime"),
        profiles_dir=str(tmp_path / "profiles"),
        session_idle_timeout="15m",
        login_max_attempts=5,
        login_lockout="15m",
    )
    defaults.update(overrides)
    settings = Settings(_env_file=None, **defaults)
    set_settings(settings)
    set_secret_provider(None)
    set_auth_service(None)
    set_registry(None)
    from app.main import create_app
    return create_app(settings), settings


@pytest.fixture
def client(tmp_path):
    app, settings = make_app(tmp_path)
    with TestClient(app, base_url="http://127.0.0.1:8080") as c:
        yield c


@pytest.fixture
def offline_client(tmp_path):
    app, settings = make_app(tmp_path, auth_mode="none")
    with TestClient(app, base_url="http://127.0.0.1:8080") as c:
        yield c


def login(client: TestClient, username="admin", password=TEST_PASSWORD):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    client.headers["x-csrf-token"] = data["csrfToken"]
    return data


@pytest.fixture
def store_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture
def local_store_env(tmp_path, store_key, monkeypatch):
    monkeypatch.setenv("TEST_STORE_KEY", store_key)
    return dict(cluster_store="local", store_key_ref="env:TEST_STORE_KEY")
