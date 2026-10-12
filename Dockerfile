# syntax=docker/dockerfile:1
# Multi-stage build, non-root UID 10001, slim patched base, no
# package managers in the runtime image, healthcheck, read-only-rootfs ready.
#
# Hardened run:
#   docker run -d --name rbacgrant -p 127.0.0.1:8080:8080 \
#     --read-only --tmpfs /run/rbac-ui:mode=0700,uid=10001 \
#     -v rbacgrant-data:/data \
#     --cap-drop ALL --security-opt no-new-privileges --init \
#     --env-file .env rbacgrant:latest
#
# The container binds 0.0.0.0, so the app demands TLS: either set
# RBAC_UI_TLS_CERT_FILE/KEY_FILE, or publish on 127.0.0.1 only (as above,
# or behind a TLS proxy) and set RBAC_UI_ALLOW_INSECURE_HTTP=true.
# AUTH_MODE=none is refused off-loopback — containers need local auth.

# ── Stage 1 · frontend build ────────────────────────────────────────────────
FROM node:22-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY frontend/ .
RUN npm run build

# ── Stage 2 · python dependencies, then the app itself ─────────────────────
FROM python:3.12-slim AS backend-deps
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore
WORKDIR /src
# Dependencies first (cached unless pyproject.toml changes) …
COPY backend/pyproject.toml ./
RUN python -c "import tomllib; deps = tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']; open('requirements.txt','w').write('\n'.join(deps))" \
 && pip install --prefix=/install -r requirements.txt
# … then the application code on top.
COPY backend/ ./
RUN pip install --prefix=/install --no-deps .

# ── Stage 3 · runtime ───────────────────────────────────────────────────────
FROM python:3.12-slim
LABEL org.opencontainers.image.title="rbacgrant" \
      org.opencontainers.image.description="Web GUI for Kubernetes RBAC manifests and kubeconfigs" \
      org.opencontainers.image.source="https://github.com/shams-imran/rbacgrant" \
      org.opencontainers.image.licenses="MIT"

# Latest security patches for the base OS, then drop apt's lists.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Dedicated non-root identity; no home, no shell.
RUN groupadd -g 10001 app && useradd -u 10001 -g app -M -s /usr/sbin/nologin app

COPY --from=backend-deps /install /usr/local
COPY backend/app /srv/backend/app
COPY --from=frontend /build/dist /srv/frontend/dist

# Generate the offline catalog at build time while still root;
# app files stay root-owned so the runtime user cannot modify the code.
RUN cd /srv/backend && python -m app.catalog.generate --builtin

# Writable dirs pre-created for plain `docker run`; with --read-only they are
# replaced by a volume (/data) and a tmpfs (/run/rbac-ui).
RUN mkdir -p /data /run/rbac-ui \
 && chown 10001:10001 /data /run/rbac-ui \
 && chmod 0700 /data /run/rbac-ui

# No package managers in the attack surface of the final image.
RUN python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true

ENV RBAC_UI_IN_CONTAINER=1 \
    RBAC_UI_BIND_ADDR=0.0.0.0 \
    RBAC_UI_DATA_DIR=/data \
    RBAC_UI_RUNTIME_DIR=/run/rbac-ui \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001
WORKDIR /srv/backend
EXPOSE 8080

# Liveness only — /healthz is unauthenticated by design.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('RBAC_UI_PORT','8080') + '/healthz', timeout=4)"

ENTRYPOINT ["python", "-m", "app.main"]
