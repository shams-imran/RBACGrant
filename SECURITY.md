# Security model

This tool stores **admin kubeconfigs for several clusters**, which makes it a
high-value target: whoever controls the app controls every registered cluster.
This file summarizes what is enforced in code and where.

## Principles (enforced, with tests)

1. **Deny by default.** Every endpoint except `/api/auth/login`, `/healthz`
   and static assets requires an authenticated session. A route-inventory test
   asserts every route declares a permission (`tests/test_auth_and_web.py`).
2. **Cluster credentials are write-only from the UI.** No API returns a stored
   kubeconfig — there is no download/view path at all (`store/base.py`).
3. **Never plaintext at rest.** Local store: AES-256-GCM, versioned header,
   cluster name as AEAD associated data (file swap/rename breaks decryption),
   0700/0600 permissions enforced at startup. Vault: KV v2, max_versions=2,
   delete destroys all versions.
4. **Never log secrets.** Structured audit events redact known field names;
   a logging filter scrubs Argon2 hashes, JWTs, PEM keys and Vault tokens.
5. **Least privilege.** App roles (viewer/editor/admin), least-privilege Vault
   policy (`deploy/vault-policy.hcl`), restricted operator bootstrap
   (`deploy/operator-restricted.yaml`), non-root read-only container.
6. **Short-lived by default.** Sessions 15m idle / 8h absolute; tokens 8h
   default / 7d cap; certs 24h default / 7d cap. Caps clamp server-side.
7. **Dangerous actions are explicit.** Dry-run → diff → confirmation; prod
   applies need the typed cluster name + step-up; guardrail overrides need
   admin + typed reason + step-up and are audited.

## Key controls in code

| Control | Where |
|---|---|
| Startup refusals (no password, auth=none with a store, multi-worker, off-loopback HTTP) | `app/settings.py::validate_startup` |
| Argon2id (m=64MiB, t=3, p=4), policy, dummy-hash timing equalization | `app/auth/passwords.py` |
| Lockout: per-IP lock + escalating delays (no per-username DoS) | `app/auth/sessions.py` |
| Session cookies: HttpOnly, SameSite=Strict, `__Host-` over HTTPS | `app/security/middleware.py` |
| CSRF synchronizer token + Origin check + Host allowlist | `app/security/middleware.py`, `deps.py` |
| Uploaded kubeconfig validation: exec/auth-provider/file-ref/TLS-bypass rejection, SSRF guard (metadata/link-local/loopback), size + alias bombs | `app/store/kubeconfig_validation.py` |
| Password rotation: changed value revokes; fetch error never revokes | `app/auth/service.py::check_rotation_once` |
| Audit log: JSON-lines, stdout + rotating 0600 file, rotation audited | `app/security/audit.py` |
| Generated-credential caps and `system:*` CSR hard block | `app/routers/k8s_routes.py`, `app/linter/guardrails.py` |
| In-browser key generation (key never reaches the server) | `frontend/src/crypto/csr.ts` |
| Private runtime dir for client cert temp files, wiped on start/stop | `app/k8s/client_factory.py` |
| Core dumps disabled | `app/main.py::_disable_core_dumps` |

## Known deviations

- **CSP**: `style-src` includes `'unsafe-inline'` because Mantine and Monaco
  inject runtime `<style>` elements. `script-src` remains strictly `'self'`
  (no inline scripts, no CDN — fonts and Monaco are bundled). Inline-style
  injection alone does not enable script execution.
- Rate limiting on general API routes is not yet implemented (login
  brute-force protection is).
- An audit hash chain and TOTP/OIDC are pending.

## Reporting

Open a private security advisory or contact the maintainer directly. Do not
open public issues for vulnerabilities.
