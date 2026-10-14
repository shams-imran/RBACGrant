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

## Running it for real

Hardened [Compose and Kubernetes manifests](https://github.com/shams-imran/RBACGrant/tree/main/deploy)
ship in the repo — read-only rootfs, all capabilities dropped, tmpfs scratch,
encrypted cluster store on a volume. The
[README](https://github.com/shams-imran/RBACGrant#running-it-properly) covers
the password hash, the store key and Vault.

Most-touched settings (full list in
[`.env.example`](https://github.com/shams-imran/RBACGrant/blob/main/.env.example)):

| Variable | Default | Purpose |
|---|---|---|
| `RBAC_UI_ADMIN_PASSWORD_HASH` | — | Argon2id hash (`rbac-ui hash-password`); **required** |
| `RBAC_UI_PUBLIC_URL` | `http://127.0.0.1:8080` | URL users open; drives Origin checks + cookie flags |
| `RBAC_UI_CLUSTER_STORE` | `none` | `none` · `local` (AES-GCM) · `vault` |
| `RBAC_UI_STORE_KEY_REF` | — | key ref for the local store |
| `RBAC_UI_MAX_TOKEN_TTL` / `MAX_CERT_TTL` | `7d` | hard caps on issued credentials |
| `RBAC_UI_ALLOWED_API_SERVERS` | — | allowlist of registrable API servers |
| `RBAC_UI_READ_ONLY` | `false` | global kill switch for cluster writes |

---

Found a security issue? See
[SECURITY.md](https://github.com/shams-imran/RBACGrant/blob/main/SECURITY.md).
Everything else → [github.com/shams-imran/RBACGrant](https://github.com/shams-imran/RBACGrant).
