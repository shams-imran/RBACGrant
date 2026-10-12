# Releasing

How a version of RBACGrant gets built, published and signed — and what someone
pulling the image can actually prove about it.

## One-time setup

### 1. Docker Hub

Create the repository (`hub.docker.com` → *Create repository*), then an access
token: **Account Settings → Personal access tokens → Generate** with
**Read & Write** scope. Copy it once; Docker Hub won't show it again.

### 2. GitHub repository configuration

**Settings → Secrets and variables → Actions**

| Kind | Name | Value |
|---|---|---|
| Secret | `DOCKERHUB_USERNAME` | your Docker Hub account or org name |
| Secret | `DOCKERHUB_TOKEN` | the access token from above |
| Variable | `IMAGE_NAME` | `shamsimran/rbacgrant` |

`IMAGE_NAME` is a *variable*, not a secret — it has to appear in the release notes
and in the signature identity so users can verify it.

Nothing else is needed. Image signing is **keyless**: the workflow asks GitHub for
a short-lived OIDC token, Sigstore issues a certificate bound to
`repo + workflow + tag`, and the signature is recorded in the public Rekor
transparency log. There is no signing key to store, rotate or leak.

### 3. Permissions

The release job already declares what it needs:

```yaml
permissions:
  contents: read
  id-token: write   # required for keyless signing
```

If your organization restricts Actions permissions, make sure
`id-token: write` is allowed, or signing fails with "no identity token".

## Cutting a release

```bash
# 1. make sure main is green
make test

# 2. tag it — annotated tags carry the author and date
git tag -a v1.0.0 -m "v1.0.0"
git push origin v1.0.0
```

That's it. The `release` workflow then:

1. **Re-runs the whole test suite** on the tagged commit.
2. **Builds** `linux/amd64` and `linux/arm64` from the same Dockerfile.
3. **Pushes** to Docker Hub as `1.0.0`, `1.0`, `1` and `latest`.
   A pre-release tag (`v1.1.0-rc1`) does *not* move `latest`.
4. **Scans** the pushed image with Trivy and fails the release on fixable
   HIGH/CRITICAL findings.
5. **Signs** the image digest with cosign.
6. **Attests** an SBOM (CycloneDX) and SLSA build provenance.
7. **Publishes a GitHub release** with the digest, the verification command and
   the SBOM attached.

Check the run's summary page for the digest.

## What a user can verify, and what it means

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/shams-imran/RBACGrant/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  shamsimran/rbacgrant@sha256:...
```

A successful verification proves:

- the image was built **by that workflow file**, in **that repository**, from a
  **tag matching `v*`** — not by someone with a stolen Docker Hub token;
- the digest has not changed since signing;
- the signature is in a public transparency log, so a backdated or quietly
  replaced signature is detectable.

It does **not** prove the source code is good. It proves provenance, not quality.

`--certificate-identity-regexp` matters: without pinning the identity, `cosign
verify` accepts a signature from *anyone*, which is no guarantee at all.

### Provenance and SBOM

```bash
# how it was built
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/shams-imran/RBACGrant/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  shamsimran/rbacgrant@sha256:... | jq -r '.payload' | base64 -d | jq .

# what is inside it
cosign download sbom shamsimran/rbacgrant@sha256:...
```

The provenance names the source commit, the workflow and the builder. If you need
to answer "which commit is running in production", that's where it comes from.

## Enforcing signatures in a cluster

If you run RBACGrant on Kubernetes, you can refuse unsigned images with a policy
controller. With [policy-controller](https://docs.sigstore.dev/policy-controller/overview/):

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: rbacgrant-must-be-signed
spec:
  images:
    - glob: "index.docker.io/shamsimran/rbacgrant**"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: '^https://github\.com/shams-imran/RBACGrant/\.github/workflows/release\.yml@refs/tags/v'
```

Kyverno's `verifyImages` rule does the same thing if that's what you already run.

## Versioning

Semantic versioning, with the caveat that this tool holds cluster credentials:

- **Patch** — fixes, dependency bumps, no config changes.
- **Minor** — new features, backward-compatible configuration.
- **Major** — anything that changes the meaning of an existing setting, the stored
  credential format, or a security default.

Security fixes get a patch release on the current minor, and the release notes say
plainly what was wrong.

## If a release goes out broken

Don't delete the tag or overwrite the image — someone may already have pulled it,
and a moved tag is exactly what signing is meant to make visible.

1. Fix forward with a new patch version.
2. On Docker Hub, the bad tag can be removed; the digest stays referenced by
   anyone who pinned it, which is the point of pinning.
3. If the issue is a security one, say so in the release notes of the fix and
   mention the affected versions.
