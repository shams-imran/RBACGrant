<!-- Docker Hub repository overview for shamsimran/rbacgrant.
     Paste into Hub → Repository → edit Overview. Keep in sync on release. -->

# RBACGrant

A web GUI that builds **Kubernetes RBAC manifests and kubeconfigs** — with a
risk linter, apply guardrails and multi-cluster support. Point it at a cluster
and grant access end to end: pick a starter template or build a Role visually,
lint it against the Kubernetes RBAC good-practices rules, dry-run it
server-side, apply it, and hand over a time-boxed kubeconfig (ServiceAccount
token or signed client certificate) in one flow.

![Grant Access flow](https://raw.githubusercontent.com/shams-imran/RBACGrant/main/docs/screenshots/02-grant-access.png)

- **17 starter templates** for the grants teams otherwise hand-roll: namespace
  admin/viewer, developer, log reader, pod debugger, incident responder,
  CI deployer, secret manager, network admin, capacity manager, and more.
- **Risk linter + guardrails**: wildcard rules, secrets access, exec,
  escalate/bind, `cluster-admin` bindings and dangerous subjects are flagged;
  the worst require an admin override with a typed reason — or are refused.
- **Credential issuing**: TokenRequest tokens and CSR-signed client certs with
  TTL caps; private keys are generated in the browser and never reach the server.
- **Can-I checks, live RBAC browsing/editing, YAML import, Helm/Kustomize export,
  append-only audit log.**

## Try it (nothing stored, no cluster needed)

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e RBAC_UI_ADMIN_PASSWORD='pick-a-password-here' \
  -e RBAC_UI_ALLOW_INSECURE_HTTP=true \
  shamsimran/rbacgrant:latest
```

Open http://127.0.0.1:8080 and log in as `admin`. There is **no default
password** — the server refuses to start without one.

> Publish on **loopback only** (`-p 127.0.0.1:8080:8080`). This app holds
> cluster admin credentials; a bare `-p 8080:8080` exposes it on every
> interface. For a real deployment, terminate TLS in front and set
> `RBAC_UI_PUBLIC_URL` to the HTTPS address.

## Supported tags

| Tag | Meaning |
|---|---|
| `1.1.0`, `1.1`, `1` | immutable release lines |
| `latest` | most recent release |

Multi-arch (`linux/amd64`, `linux/arm64`); `docker pull` picks the right one.
For production, pin the digest from the
[GitHub release notes](https://github.com/shams-imran/RBACGrant/releases) —
tags move, digests do not.

## Persistent deployment

Hardened Compose and Kubernetes manifests ship in
[`deploy/`](https://github.com/shams-imran/RBACGrant/tree/main/deploy):
read-only rootfs, non-root UID 10001, all capabilities dropped, tmpfs scratch,
encrypted cluster store on a volume. The
[README](https://github.com/shams-imran/RBACGrant#running-it-properly) walks
through the password hash, the store key and Vault integration.

## Key configuration (env vars, `RBAC_UI_` prefix)

| Variable | Default | Purpose |
|---|---|---|
| `RBAC_UI_ADMIN_PASSWORD_HASH` | — | Argon2id hash (`rbac-ui hash-password`); required |
| `RBAC_UI_PUBLIC_URL` | `http://127.0.0.1:8080` | URL users open; drives Origin checks + cookie flags |
| `RBAC_UI_CLUSTER_STORE` | `none` | `none`, `local` (AES-GCM encrypted) or `vault` |
| `RBAC_UI_STORE_KEY_REF` | — | 32-byte base64 key ref for the local store |
| `RBAC_UI_MAX_TOKEN_TTL` / `RBAC_UI_MAX_CERT_TTL` | `7d` | hard caps on issued credentials |
| `RBAC_UI_ALLOWED_API_SERVERS` | — | allowlist of registrable API servers |
| `RBAC_UI_READ_ONLY` | `false` | global kill switch for cluster writes |
| `RBAC_UI_AUDIT_LOG_FILE` | — | JSON-lines audit log path |

Full reference with comments:
[`.env.example`](https://github.com/shams-imran/RBACGrant/blob/main/.env.example).

## Image security

Non-root (UID 10001), no package managers in the final layer, read-only-rootfs
ready, Trivy-gated at release, SLSA provenance and SBOM attached. Every release
is signed keylessly with cosign:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/shams-imran/RBACGrant/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  shamsimran/rbacgrant:1.1.0
```

## Links

- **Source:** https://github.com/shams-imran/RBACGrant
- **Issues:** https://github.com/shams-imran/RBACGrant/issues
- **Security policy:** [SECURITY.md](https://github.com/shams-imran/RBACGrant/blob/main/SECURITY.md)
- **License:** MIT
