# Release process

How a Correlic release is cut, what gets signed and where, how to rotate the
optional GPG key, and how anyone can verify the result. The verification
commands are the same as in [`../../SECURITY.md`](../../SECURITY.md)
("Verifying a release"); the threat model for the pipeline is in
[`THREAT_MODEL.md`](THREAT_MODEL.md) (attacker A4).

## Who and what

A release is cut by a repository maintainer (`.github/CODEOWNERS`) from
`main`. Every component ships under one version `vX.Y.Z`: the five
container images, the Linux bundles and packages, the Windows bundle. Nothing
is built on a maintainer's machine; the three release workflows in
`.github/workflows/` build everything from the repository on GitHub-hosted
runners. There are no release secrets besides the optional GPG key: image
pushes use the job's `GITHUB_TOKEN`, and all signing is Sigstore keyless
with the job's OIDC identity.

## Cutting a release

1. **Prepare the change on `main`.** Move the `## Unreleased` section of
   `CHANGELOG.md` under a new `## vX.Y.Z (YYYY-MM-DD)` heading with the
   release link; bump the version pinned in `install/install.sh`,
   `install/install.ps1` and the README's "Current release" line in the same
   pull request. Merge it; CI (`ci.yml`) and the security workflow
   (`security.yml`) must be green on the merge commit.
2. **Dispatch `Release container images`** (`release-images.yml`) on `main`
   with `version: vX.Y.Z`. It builds the linux/amd64 + linux/arm64 images,
   pushes them to `ghcr.io/fuloxdev/<image>:vX.Y.Z` and `:latest`, signs them,
   attaches the SBOM attestations, verifies both, uploads the SBOMs as
   workflow artifacts and scans the images with Trivy (results in the
   Security tab, non-blocking).
3. **Dispatch `Build Linux bundle`** (`build-linux-bundle.yml`) and
   **`Build Windows bundle`** (`build-windows-bundle.yml`) on `main` with the
   same version. Each builds its assets, writes the SBOMs, signs every asset
   and the checksum file, verifies the signatures in the same job, and
   attaches everything to a **draft** GitHub release named `vX.Y.Z` (created
   by the first of the two to finish; the second adds its assets to it).
4. **Inspect the draft release.** Expected assets:

   | Linux | Windows |
   |---|---|
   | `correlic-linux-vX.Y.Z.tar.gz`, `correlic-linux-vX.Y.Z-arm64.tar.gz` | `correlic-windows-vX.Y.Z.zip` |
   | `correlic_X.Y.Z_amd64.deb`, `correlic_X.Y.Z_arm64.deb` | `SHA256SUMS-windows.txt` |
   | `correlic-X.Y.Z-1.x86_64.rpm`, `correlic-X.Y.Z-1.aarch64.rpm` | |
   | `correlic-linux-repo-vX.Y.Z.tar.gz` (apt/yum trees) | |
   | `SHA256SUMS-linux.txt` | |
   | one `<asset>.sigstore.json` per asset above and per checksum file | same |
   | one `<asset>.spdx.json` per tar.gz, deb, rpm | `correlic-windows-vX.Y.Z.zip.spdx.json` |

   Paste the release notes (the CHANGELOG section) into the description.
5. **Publish the release.** Publishing creates the `vX.Y.Z` tag at the
   commit the workflows built. The tag push would re-trigger the three
   workflows; they are idempotent (same inputs, images re-pushed by digest,
   assets re-attached), but cancel them if you want to avoid the duplicate
   run.
6. **Verify from a clean machine** with the commands below, then update the
   README's download links if the asset names changed.

## What is signed, by what, and where it lives

| Artifact | Signature | Where | Identity in the certificate |
|---|---|---|---|
| Image index and each platform manifest, all five images | `cosign sign --recursive` (keyless) | GHCR, attached to the digest (OCI referrers) | `.../.github/workflows/release-images.yml@<ref>` |
| Per-platform SPDX SBOM of each image | `cosign attest --type spdxjson` | GHCR, attached to the index digest; also a workflow artifact `sbom-<image>-<version>` | same |
| SLSA provenance (`mode=max`) and BuildKit SBOM | docker buildx attestations | inside the image index (`docker buildx imagetools inspect`) | n/a (unsigned in-toto statements; the signed image digest covers them) |
| Every Linux and Windows asset and both checksum files | `cosign sign-blob --bundle` (keyless) | GitHub release, `<asset>.sigstore.json` | `.../build-linux-bundle.yml@<ref>` or `.../build-windows-bundle.yml@<ref>` |
| Bundle and package SBOMs | listed in the signed `SHA256SUMS-*.txt` | GitHub release, `<asset>.spdx.json` | covered by the checksum file's signature |
| `.deb` / `.rpm` (optional) | GPG, `dpkg-sig` / `rpm --addsign` | inside the packages; public key `correlic.gpg.key` in `correlic-linux-repo-*.tar.gz` | the maintainer's GPG key |

Every signature is recorded in the public Rekor transparency log, so the
set of artifacts ever signed under this repository's identity is auditable
(`rekor-cli search --email` does not apply to workflow identities; search by
artifact hash: `rekor-cli search --sha <sha256>`).

The certificate identity encodes the workflow file and the ref. A release cut
by `workflow_dispatch` on `main` carries `@refs/heads/main`; a tag-triggered
rebuild carries `@refs/tags/vX.Y.Z`. Both are legitimate; the verification
regexps in `SECURITY.md` match either.

## Secrets and keys

| Secret | Required | Used by | Notes |
|---|---|---|---|
| `GITHUB_TOKEN` (automatic) | yes | all three workflows | `packages: write` to push images, `contents: write` to attach assets, `security-events: write` to upload Trivy results. Scoped to the run; nothing to rotate. |
| OIDC token (`id-token: write`) | yes | all three workflows | Exchanged with Fulcio for a short-lived signing certificate. Nothing stored, nothing to rotate. |
| `GPG_PRIVATE_KEY` (repository secret) | no | `build-linux-bundle.yml`, step "Sign packages" | ASCII-armoured private key **without a passphrase** (the step runs `gpg --batch --import` and `dpkg-sig`/`rpm --addsign` non-interactively). When unset the step is skipped and the packages carry only the Sigstore signature. |

### Rotating the GPG key

1. Generate a new key on a trusted machine:
   `gpg --quick-generate-key "Correlic Packages <noreply@correlic.invalid>" ed25519 sign 2y`
   (use your real contact address; no passphrase, or remove it with
   `gpg --edit-key <id> passwd` before exporting).
2. Export it: `gpg --armor --export-secret-keys <id> > key.asc`.
3. Replace the repository secret `GPG_PRIVATE_KEY` with the contents of
   `key.asc` (Settings → Secrets and variables → Actions). Delete `key.asc`
   and the key from the machine if it should only live in the secret store.
4. The next Linux release embeds the new public key as `correlic.gpg.key`
   inside the repo tarball. Self-hosters using the apt/yum trees import it
   again; announce the fingerprint in the release notes.
5. Revoke the old key (`gpg --gen-revoke`) and publish the revocation
   certificate in the release notes. Packages signed with the old key remain
   valid for anyone who already trusts it; the Sigstore signature on the same
   file is unaffected.

### If the pipeline is compromised

Keyless signing has no key to revoke. If a maintainer account or a workflow
is compromised: delete the affected release and image tags, publish a
GitHub Security Advisory naming the affected versions and the Rekor log
entries (the log is append-only; the entries stay as evidence), rotate every
secret in the repository, force-push nothing (keep history for forensics),
and cut a new patch release from a reviewed commit.

## Verifying a release

```bash
V=vX.Y.Z
ISS=https://token.actions.githubusercontent.com

# Images (cosign 3.x):
cosign verify --output text \
  --certificate-identity-regexp '^https://github.com/FuloxDev/correlic/\.github/workflows/release-images\.yml@' \
  --certificate-oidc-issuer "$ISS" ghcr.io/fuloxdev/correlic:$V
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp '^https://github.com/FuloxDev/correlic/\.github/workflows/release-images\.yml@' \
  --certificate-oidc-issuer "$ISS" ghcr.io/fuloxdev/correlic:$V > /dev/null && echo "SBOM attestation ok"

# Assets:
BASE=https://github.com/FuloxDev/correlic/releases/download/$V
for f in correlic-linux-$V.tar.gz SHA256SUMS-linux.txt; do
  curl -fsSLO "$BASE/$f" && curl -fsSLO "$BASE/$f.sigstore.json"
  cosign verify-blob --bundle "$f.sigstore.json" \
    --certificate-identity-regexp '^https://github.com/FuloxDev/correlic/\.github/workflows/build-linux-bundle\.yml@' \
    --certificate-oidc-issuer "$ISS" "$f"
done
sha256sum --ignore-missing -c SHA256SUMS-linux.txt
```

A verification failure on a published release is a security incident:
report it through the private vulnerability reporting link in
`SECURITY.md`, not in a public issue.

## Changing the pipeline

- Third-party actions are pinned to a release tag today
  (`sigstore/cosign-installer@v4.1.2`, `anchore/sbom-action/download-syft@v0`,
  `aquasecurity/trivy-action@0.35.0`, `ossf/scorecard-action@v2.4.4`,
  `github/codeql-action/*@v4`, `actions/dependency-review-action@v4`).
  Once the Scorecard baseline is green, switch them to commit SHAs with the
  version in a trailing comment; Dependabot's `github-actions` updates keep
  SHA pins current.
- Any change to a release workflow needs a code owner review and a dry run
  via `workflow_dispatch` with a throwaway version (`v0.0.0-test`); delete
  the draft release and the image tags afterwards.
- Never add a step that prints secrets, and never add long-lived signing
  keys: keyless signing is the point.
