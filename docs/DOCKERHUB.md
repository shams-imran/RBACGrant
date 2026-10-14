# RBACGrant

[![Source](https://img.shields.io/badge/source-GitHub-181717?logo=github)](https://github.com/shams-imran/RBACGrant)
[![Release](https://img.shields.io/github/v/release/shams-imran/RBACGrant?color=2496ED)](https://github.com/shams-imran/RBACGrant/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/shams-imran/RBACGrant/ci.yml?branch=main&label=CI)](https://github.com/shams-imran/RBACGrant/actions)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/shams-imran/RBACGrant/blob/main/LICENSE)

**A web GUI for Kubernetes RBAC** — build Roles and RoleBindings visually or
from 17 starter templates, lint them against the RBAC good-practices rules,
dry-run and apply to your clusters, and hand over time-boxed kubeconfigs.
Stop hand-writing RBAC YAML and hoping it's safe.

| | |
|---|---|
| **Source & docs** | [github.com/shams-imran/RBACGrant](https://github.com/shams-imran/RBACGrant) |
| **Issues** | [GitHub issues](https://github.com/shams-imran/RBACGrant/issues) |
| **Platforms** | `linux/amd64` · `linux/arm64` (one manifest list) |
| **Runs as** | non-root UID 10001 · read-only rootfs ready · no package managers |
| **License** | MIT |

![Grant Access flow](https://raw.githubusercontent.com/shams-imran/RBACGrant/main/docs/screenshots/02-grant-access.png)

---

## Quick start

Try it with nothing stored and no cluster attached:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e RBAC_UI_ADMIN_PASSWORD='pick-a-password-here' \
  -e RBAC_UI_ALLOW_INSECURE_HTTP=true \
  shamsimran/rbacgrant:latest
```

Open http://127.0.0.1:8080 and log in as `admin` with the password you set.
There is **no default password** — the server refuses to start without one.

> ⚠️ Publish on **loopback only** (`-p 127.0.0.1:8080:8080`). This app holds
> cluster admin credentials; a bare `-p 8080:8080` exposes it on every
> interface. For real use, terminate TLS in front and set
> `RBAC_UI_PUBLIC_URL` to the HTTPS address.

## What's inside

- 🧩 **17 starter templates** — namespace admin/viewer, developer, log reader,
  pod debugger, incident responder, CI deployer, secret manager, network
  admin, capacity manager, and more: fill in `${team}` and `${namespace}`, done.
- 🚦 **Risk linter + guardrails** — wildcards, secrets access, exec,
  `escalate`/`bind`, `cluster-admin` bindings and dangerous subjects are
  flagged; the worst need an admin override with a typed reason, or are refused outright.
- 🔑 **Credential issuing** — ServiceAccount tokens (TokenRequest) and
  CSR-signed client certificates with TTL caps; private keys are generated in
  the browser and never reach the server.
- 🔍 **Can-I checks**, live RBAC browse/edit/delete, YAML import,
  Helm/Kustomize/zip export, append-only audit log, multi-cluster with an
  encrypted credential store.

## Tags

| Tag | Use it for |
|---|---|
| `1.1.0` | pinning an exact release |
| `1.1`, `1` | tracking a release line |
| `latest` | trying it out |

For production, pin the **digest** from the
[release notes](https://github.com/shams-imran/RBACGrant/releases) — tags
move, digests don't. Every release is Trivy-gated, ships an SBOM and SLSA
provenance, and is signed with cosign:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/shams-imran/RBACGrant/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  shamsimran/rbacgrant:1.1.0
```

## Running it for real (persistent, with storage)

Saved clusters live in an AES-GCM-encrypted store on a volume, locked by a
32-byte key that must live **outside** the data volume. One-time setup:

```bash
# generate the store key — keep a backup; a lost key means re-adding every cluster
mkdir -p ~/.config/rbacgrant
head -c 32 /dev/urandom | base64 > ~/.config/rbacgrant/store.key
chmod 600 ~/.config/rbacgrant/store.key

# hash the admin password (prompts twice, prints the hash)
docker run --rm -it --entrypoint python shamsimran/rbacgrant:1.1.0 -m app.cli hash-password
```

### docker run

```bash
docker run -d --name rbacgrant \
  -p 127.0.0.1:8080:8080 \
  -e RBAC_UI_ADMIN_PASSWORD_HASH='$argon2id$...paste-your-hash-here...' \
  -e RBAC_UI_ALLOW_INSECURE_HTTP=true \
  -e RBAC_UI_CLUSTER_STORE=local \
  -e RBAC_UI_STORE_KEY_REF=file:/etc/rbac-ui/store.key \
  -e RBAC_UI_AUDIT_LOG_FILE=/data/audit.log \
  -v rbacgrant-data:/data \
  -v ~/.config/rbacgrant/store.key:/etc/rbac-ui/store.key:ro \
  --restart unless-stopped \
  shamsimran/rbacgrant:1.1.0
```

`rbacgrant-data` keeps the encrypted cluster store and the audit log across
restarts and upgrades; the key is mounted read-only from the host. Keep the
single quotes around the hash — it contains `$`.

> Mapping a different host port? Set `RBAC_UI_PUBLIC_URL` to match
> (e.g. `-p 127.0.0.1:9090:8080` needs
> `-e RBAC_UI_PUBLIC_URL=http://127.0.0.1:9090`), or logins fail the
> cross-origin check with a 403.

### docker compose

```yaml
services:
  rbacgrant:
    image: shamsimran/rbacgrant:1.1.0
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"     # loopback only — TLS proxy in front for real use
    env_file: .env                # RBAC_UI_* settings incl. the password hash —
                                  # an env_file avoids compose eating the $ in it
    environment:
      RBAC_UI_ALLOW_INSECURE_HTTP: "true"
      RBAC_UI_CLUSTER_STORE: local
      RBAC_UI_STORE_KEY_REF: file:/etc/rbac-ui/store.key
      RBAC_UI_AUDIT_LOG_FILE: /data/audit.log
    volumes:
      - rbacgrant-data:/data                               # encrypted store + audit log
      - ./store.key:/etc/rbac-ui/store.key:ro              # AES key, outside the data volume
    # hardening (optional but free):
    read_only: true
    tmpfs:
      - /run/rbac-ui:rw,noexec,nosuid,size=16m,mode=0700,uid=10001,gid=10001
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]

volumes:
  rbacgrant-data:
```

A fuller hardened Compose file and a Kubernetes manifest ship in the repo's
[`deploy/`](https://github.com/shams-imran/RBACGrant/tree/main/deploy)
directory, and the
[README](https://github.com/shams-imran/RBACGrant#running-it-properly) covers
TLS, Vault integration and multi-user setup.

### Configuration

Full commented reference:
[`.env.example`](https://github.com/shams-imran/RBACGrant/blob/main/.env.example).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `RBAC_UI_ADMIN_PASSWORD_HASH` | **yes** | — | Argon2id hash; there is no default password |
| `RBAC_UI_ALLOW_INSECURE_HTTP` | **yes, in a container** | `false` | acknowledges TLS terminates outside (or nowhere, on loopback) |
| `RBAC_UI_CLUSTER_STORE` | to save clusters | `none` | `none` · `local` (AES-GCM) · `vault` |
| `RBAC_UI_STORE_KEY_REF` | with `local` store | — | e.g. `file:/etc/rbac-ui/store.key`; 32-byte base64, 0600 |
| `RBAC_UI_PUBLIC_URL` | off-loopback | `http://127.0.0.1:8080` | exact URL users open — Origin checks and cookie flags derive from it |
| `RBAC_UI_ALLOWED_HOSTS` | off-loopback | `localhost,127.0.0.1` | Host-header allowlist (anti DNS-rebinding) |
| `RBAC_UI_AUDIT_LOG_FILE` | recommended | — | JSON-lines audit trail, e.g. `/data/audit.log` |
| `RBAC_UI_MAX_TOKEN_TTL` / `MAX_CERT_TTL` | no | `7d` | hard caps on issued credentials |
| `RBAC_UI_ALLOWED_API_SERVERS` | no | — | allowlist of registrable API servers |
| `RBAC_UI_READ_ONLY` | no | `false` | global kill switch for cluster writes |

---

Found a security issue? See
[SECURITY.md](https://github.com/shams-imran/RBACGrant/blob/main/SECURITY.md).
Everything else → [github.com/shams-imran/RBACGrant](https://github.com/shams-imran/RBACGrant).
