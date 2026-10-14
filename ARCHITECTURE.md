# RBACGrant — Architecture

How the backend and frontend fit together, end to end.

## The big picture

One Python process does everything. FastAPI serves the JSON API **and** the built
React bundle as static files from the same origin — there is no separate web
server, no CORS, no second deployment. The browser talks to `/api/*`; anything
else falls through to `index.html` for client-side routing
(`backend/app/main.py:107`).

```
browser (React SPA, Mantine + Monaco)
   │  same-origin fetch, session cookie + CSRF header
   ▼
SecurityMiddleware  ── Host allowlist, Origin check, body caps, CSP headers
   ▼
require("permission") dependency  ── session lookup + CSRF + role check
   ▼
routers/  auth · builder · clusters · k8s
   ▼
domain layer:  models → generators → linter       (pure, offline, no cluster)
               store → secrets                    (credentials at rest)
               k8s/  client_factory → operations   (live cluster)
   ▼
audit log (JSON lines, stdout + rotating 0600 file)
```

The shape worth internalizing: **the offline path and the cluster path are
completely separate stacks**, and the offline one has no dependency on the
other. You can run the whole builder/linter/export flow with
`RBAC_UI_CLUSTER_STORE=none` and nothing ever touches a cluster.

---

## Backend

### Composition root

`create_app()` in `backend/app/main.py:45` is the only place wiring happens, in
a fixed order: logging + redaction → `validate_startup()` → audit log →
`SecretProvider` → `AuthService` → `ClusterRegistry` → routers. Each of those
lands in a module-level singleton accessed via `get_X()` (`get_settings`,
`get_audit`, `get_auth_service`, `get_registry`, `get_secret_provider`). Crude
compared to real DI, but it makes tests easy — `conftest.py` just calls the
`set_X()` setters.

`validate_startup()` (`settings.py:209`) is a refusal gate, not a warning list.
Auth off + a cluster store configured, local store without a key, off-loopback
plain HTTP, >1 worker — each raises `StartupError` and the process exits 1.
Misconfiguration can't silently degrade into something insecure.

### Layers

| Layer | Path | Role |
|---|---|---|
| Settings | `settings.py` | One pydantic-settings class, `RBAC_UI_` prefix, `.env` resolved from repo root. Duration/size strings (`"8h"`, `"64MiB"`) parsed into `*_s` / `*_bytes` properties |
| Models | `models/rbac.py`, `models/cluster.py` | Pydantic *form state*, not K8s API objects. This is where the RBAC rules of the universe live: a Role needs a namespace, a ClusterRoleBinding can't reference a Role, `nonResourceURLs` is ClusterRole-only, names unique per bundle. Invalid input is a 422 before any logic runs |
| Generators | `generators/` | `manifests.py` turns models → K8s dicts → multi-doc YAML. `exporters.py` adds zip/kubectl/kustomize. `kubeconfig.py` assembles a kubeconfig |
| Linter | `linter/` | `rules.py` has ~30 rules (`RL-C1`…`RL-I1`) over severity critical→info, plus `least_privilege_score()`. `guardrails.py` layers *policy* on top: hard blocks (no override) vs. override-required |
| Store | `store/` | `ClusterStore` ABC with three impls: `NoneStore`, `LocalEncryptedStore` (AES-256-GCM), `VaultClusterStore` (KV v2) |
| Secrets | `secrets/provider.py` | `env:` / `file:` / `vault:` / `sops:` ref resolution behind one `get(ref) -> SecretStr`, TTL-cached |
| K8s | `k8s/` | `client_factory.py` builds a short-lived `ApiClient`; `operations.py` is every cluster call |

### The central abstraction: `Bundle`

Everything flows through `Bundle` (`models/rbac.py`) — a list of roles +
bindings + service accounts. The frontend builds one, posts it, and the same
object drives preview, lint, guardrails, export, dry-run and apply. One
pipeline:

```
Bundle → bundle_manifests() → list[dict]  ─┬→ to_yaml()             (preview, export)
                                           ├→ lint_manifests()      (findings, score)
                                           ├→ evaluate_guardrails() (block/override)
                                           └→ server_side_apply()   (dry-run or real)
```

Because the linter works on *manifests*, not on `Bundle`, the identical rules
run against live cluster RBAC read back from the API server — the "RBAC Objects"
page lints what's already in the cluster with the same code
(`linter/rules.py:1-3`).

### Authorization is declarative

There are no permission checks inside handlers. Every route declares one:

```python
async def apply(..., session=require("rbac:apply")) -> dict:
```

`require()` (`security/deps.py:51`) is a dependency factory that resolves the
session cookie, validates the CSRF header, then checks the permission against a
static role matrix (`viewer`/`editor`/`admin` in `auth/service.py:23`). It
stashes `dependency.required_permission` so a test can walk the route table and
assert nothing is unguarded. With `AUTH_MODE=none` it fabricates an in-request
admin session — which is why startup refuses that mode unless you're on loopback
with no store.

Two orthogonal gates stack on top for dangerous operations:

- `require_step_up()` — password re-entered within `step_up_window` (5m).
  Returns 403 with `X-Step-Up-Required: true`, which the frontend turns into a
  modal and an automatic retry.
- `require_writable()` — global read-only kill switch.

The prod-apply path in `k8s_routes.py:198` is the clearest example of
composition: hard blocks → 403 unconditionally; typed cluster name → 422;
step-up; then if the guardrails want an override, `admin` role **and** a typed
reason **and** step-up, with the reason written to the audit log.

### Credential handling

This is the part with the most deliberate design, worth tracing:

1. A kubeconfig uploaded through the wizard is **untrusted input**.
   `store/kubeconfig_validation.py` safe-loads it with bounded aliases, rejects
   all local file references (`certificate-authority`, `client-key`,
   `tokenFile`), gates `exec` plugins against an allowlist, resolves the server
   URL and runs an SSRF check against link-local/metadata/loopback addresses,
   then **normalizes it to a single context**.

   The SSRF check resolves the hostname *before* any connect, so a DNS name
   pointing at `127.0.0.1` is caught too. Metadata and link-local targets are
   unconditional refusals; loopback is the one case with an escape hatch,
   `RBAC_UI_ALLOW_LOOPBACK_API_SERVERS`, because a developer running the app on
   their own machine against k3d/kind/OrbStack has a legitimately loopback API
   server. The flag is scoped to that: it never relaxes the metadata or
   link-local rules. Note that it is only meaningful when the app's loopback
   *is* the cluster's — inside a container or pod, `127.0.0.1` is that
   namespace's own, and the address has to be rewritten to a reachable one
   (`kubernetes.default.svc` for the cluster the app is deployed in) instead.

2. Saving encrypts it with AES-256-GCM where **the cluster name is the AEAD
   associated data** — rename a file on disk and decryption fails
   (`store/local_encrypted.py:85`). A 16-byte `key_id` in the header gives a
   clear "wrong key, run rotate-key" error instead of a tag failure.
3. No API route ever returns a stored kubeconfig.
   `ClusterStore.get_kubeconfig()` is documented server-side-only; list
   endpoints return `ClusterMetadata`, which has no credential fields at all.
4. To use one, `api_client_for()` (`k8s/client_factory.py:40`) is a context
   manager: `mkdtemp` inside a 0700 runtime dir (`/dev/shm` on Linux, never
   `/tmp`), load, yield, `rmtree`. The dir is also wiped on startup and
   shutdown.
5. Issued credentials are **never stored**. SA tokens come from TokenRequest
   clamped to `max_token_ttl`; user certs go through a CSR whose private key was
   generated in the browser — the server only ever sees the CSR.

### Error and log discipline

`K8sOperationError` + the `@_client_safe` decorator (`k8s/operations.py:40`)
convert every `ApiException` and transport failure into a redacted, client-safe
error with a sane status, so an unreachable cluster is a 502 with a readable
message rather than a 500 with a stack trace. On the logging side,
`security/redaction.py` installs a `logging.Filter` that regex-scrubs argon2
hashes, JWTs, PEM private keys and Vault tokens from *every* log line, and
`redact_fields()` blanks known secret keys in audit events before they're
written.

---

## Frontend

React 18 + TypeScript + Vite + Mantine v7. `npm run build` emits
`frontend/dist/`, which the backend mounts. In dev, Vite proxies `/api` to
`:8080` (`vite.config.ts`).

### Structure

```
main.tsx          providers + self-hosted fonts + Monaco wired to a local worker
 └ App.tsx        AuthProvider → ClusterProvider → AppShell + routes
    ├ pages/      10 route components
    ├ components/ RuleEditor, YamlPreview, Findings, ExportBar,
    │             ApplyToCluster, ExpiryPicker, StepUpModal, EnvBadge
    ├ api/        client.ts (the single fetch wrapper) + types.ts
    ├ hooks.ts    useDiscovery, useCatalog, usePreview, useAppConfig
    ├ crypto/     csr.ts — WebCrypto keygen + CSR + kubeconfig assembly
    └ lib/        kubeconfig.ts — pure merge/split logic (has unit tests)
```

No Redux, no React Query. State is `useState` in page components, with exactly
two contexts for what's genuinely global.

### The two contexts

**`AuthContext`** owns the session. `refresh()` hits `/api/auth/me` and —
importantly — hands the returned CSRF token to `setCsrfToken()` in the API
client module. So the token lives in a module variable, not in React state,
which is why any call site can attach it without prop-drilling. The client
dispatches a `rbac-ui:unauthenticated` window event on any 401, and the provider
listens and clears the session — session expiry anywhere bounces you to login
without every page handling it.

**`ClusterContext`** owns the cluster list and the active selection. There is
no implicit "current context": every cluster API call carries the name
in the path (`/api/clusters/{cluster}/...`). The selection persists in
`localStorage` and switching fires a `rbac-ui:cluster-switched` event so pages
can drop stale discovery state.

### `api/client.ts` — one choke point

Every request goes through it: same-origin, `credentials: 'same-origin'`, CSRF
header on non-GET, 401 → event, non-OK → `ApiError` carrying `status`, `detail`
and `stepUpRequired` (read off the response header). There's a nice touch at
line 48: a 200 whose content-type isn't JSON means the request fell through to
the SPA fallback, so it throws "the server is probably running an older build;
restart it" instead of a confusing JSON parse error.

### The frontend's real job: assemble a `Bundle`

Pages are thin form state over the shared `Bundle` type. `GrantAccess.tsx` — the
flagship page, 628 lines — is the pattern: a pile of `useState` for the form,
then a `useMemo` that composes a `Bundle` from it (line 141), then
`usePreview(bundle)`, which debounces 250ms and POSTs to `/api/preview`,
returning `{yaml, findings, score}` for the Monaco pane and the findings list.

That's the key design decision: **YAML generation and linting are never
duplicated client-side.** The browser renders what the server produced, so
preview and apply can't drift. The cost is a round-trip per keystroke-batch; the
debounce absorbs it.

`api/types.ts` hand-mirrors the pydantic models. No codegen, so it's
drift-by-discipline.

### Discovery-driven pickers

`useDiscovery(clusterName)` fetches `/api/clusters/{name}/discovery`
(namespaces, API groups/resources incl. CRDs, service accounts, roles, server
version) with a module-level cache and stale-while-revalidate, so a just-applied
role shows up in the picker. `liveCatalog()` (`hooks.ts:21`) prefers the
cluster's real API surface and falls back to the shipped offline catalog
(`catalog-1.24`…`1.31.json`) when no cluster is connected. Same pickers,
graceful degradation.

### Two things the frontend does that the backend deliberately cannot

1. **User-cert keygen** (`crypto/csr.ts`): WebCrypto generates an ECDSA P-256
   key, `@peculiar/x509` builds a CSR with `CN=username, O=group…`, only the CSR
   PEM is posted. The server returns the signed cert plus cluster details, and
   `assembleUserKubeconfig()` stitches the final kubeconfig together in the
   page. The private key never crosses the network.
2. **Kubeconfig merge/split** (`lib/kubeconfig.ts`, the Merge/Split page): pure
   client-side manipulation with explicit conflict resolution. Nothing is
   uploaded, so it works on configs the server should never see — and it's the
   only module with real unit tests (`kubeconfig.test.ts`, vitest).

### Step-up as a retry loop

The pattern recurs across pages: catch the error, check `err.stepUpRequired`,
stash the failed operation in a `retry` state, open `StepUpModal`; on success
the modal calls `onSuccess` which re-invokes the stashed closure. The permission
gate lives entirely on the server; the UI just reacts to the 403.

---

## Supporting pieces

- **CLI** (`app/cli.py`, installed as `rbac-ui`): `hash-password`,
  `store verify`, `store rotate-key`, `store migrate --from local --to vault`.
  Operational tasks that shouldn't be HTTP endpoints.
- **Container**: three-stage Dockerfile (node build → pip prefix install → slim
  runtime), non-root uid 10001, catalog pre-generated at build time,
  `pip`/`setuptools` uninstalled from the final image, designed for
  `--read-only` with a tmpfs runtime dir.
- **Tests**: `backend/tests/` — six pytest files covering generators, linter,
  store, kubeconfig validation, auth/web hardening and the builder API.
  `make test` runs those plus `tsc -b`.

---

## Known doc drift

- The README points at `deploy/operator-restricted.yaml`,
  `deploy/operator-full.yaml` and `deploy/vault-policy.hcl`, but `deploy/` only
  holds `docker-compose.yaml`, `kubernetes.yaml` and a local `data/` dir. Those
  operator identities actually live as
  `backend/app/templates/operator-{restricted,full}.json`, served through the
  Templates page.
- `generators/kubeconfig.py:46` and `k8s/operations.py:18` still say
  `k8s-rbac-builder` in the generated-file banner and the apply `fieldManager`,
  from before the rename to RBACGrant.
