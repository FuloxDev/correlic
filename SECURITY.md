# Security policy

Correlic is a security monitor, so a weakness in Correlic is a weakness in
the thing it protects. Reports about Correlic itself get priority over
feature work. This document covers supported versions, how to report, what is
in scope, how the system is designed to be secure, what a self-hoster should
do, and how to verify that a release is what the project built.

Related documents: [`backend/docs/THREAT_MODEL.md`](backend/docs/THREAT_MODEL.md)
(assets, trust boundaries, attacker models, what is and is not detected) and
[`backend/docs/RELEASE_PROCESS.md`](backend/docs/RELEASE_PROCESS.md) (how a
release is cut and signed).

## Supported versions

| Version | Supported |
|---|---|
| Newest release (see the [releases page](https://github.com/FuloxDev/correlic/releases)) | Yes: security fixes ship as the next patch release |
| Older releases | No: upgrade; fixes are not backported |
| `main` between releases | Best effort: fixed as part of the next release |

All components (backend, agent, `correlic-hook`, dashboard, proxy,
installers, container images) are released together under one version.

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting for this repository:

**https://github.com/FuloxDev/correlic/security/advisories/new**

Include the version (the release tag, image tag or release asset name you
installed), the component, reproduction steps or a proof of concept, and the
impact you believe it has. Reports from automated scanners are welcome when
they come with a reproduction; a bare scanner export is not a report.

There is no bug bounty. Credit is given in the advisory and the release notes
unless you prefer otherwise.

### Response targets

| Stage | Target |
|---|---|
| Acknowledgement | 3 days |
| Triage decision (confirmed / not a vulnerability / needs more information) | 7 days |
| Fix or mitigation for a confirmed critical or high severity issue | 14 days, as a patch release plus a GitHub Security Advisory |
| Fix for a confirmed medium or low severity issue | next planned release, at most 90 days |
| Public disclosure | with the release; earlier by agreement with the reporter; at the latest 90 days after triage if no fix is possible |

Severity follows the GitHub advisory scale (CVSS 3.1). An advisory is
published for every confirmed vulnerability, and the fix is listed in
`CHANGELOG.md` under "Security".

## Scope

In scope: everything in this repository as released: the backend (`backend/`),
the host agent and `correlic-hook` (`agent/`), the dashboard (`ui/`), the
proxy (`ui-proxy/`), the installers and packaging (`install/`, `Dockerfile`,
`entrypoint.sh`), the release workflows (`.github/workflows/`) and the
published images and bundles. Examples of what we want to hear about:

- authentication or authorization bypass (agent key reaching dashboard
  routes, member acting as admin, cross-organisation data access);
- an agent or hook that can be made to send data elsewhere, or a backend that
  can be made to fetch internal addresses (SSRF through notifications or AI
  providers);
- injection in the ingest path (events that corrupt detection state, SQL or
  Cypher injection, stored XSS in the dashboard);
- a way for an unprivileged process on a monitored host to crash the agent,
  starve the ring buffers or feed it forged events;
- secrets leaking into logs, API responses, SBOMs or release assets;
- a release pipeline weakness (unsigned or mis-signed assets, unpinned
  download, writable cache poisoning).

Out of scope:

- Anything that requires root (or Administrator) on the monitored host. Root
  can stop the agent; that is a documented limit, not a vulnerability. See
  the threat model.
- Detection gaps: an AI agent action that Correlic does not flag is a
  detection issue; open a regular issue with the technique, it will be
  tracked as a rule or coverage improvement.
- Vulnerabilities in third-party software redistributed unmodified in the
  bundles and the all-in-one image (PostgreSQL, Neo4j, Node.js, the JRE)
  unless Correlic's packaging or defaults make them exploitable. Report those
  upstream; we pick up fixed versions in the next release.
- Missing security headers or configuration on a reverse proxy that you put
  in front of the dashboard.
- Denial of service by event volume from a host you administer.
- The macOS preview's documented limitations (`backend/docs/MACOS_AGENT.md`).

## Security design

The one-page version. Code paths are given so you can check the claims.

**Agent to backend.** Agents talk HTTPS only (`agent/internal/config/config.go`
rejects `http://` URLs unless `allow_insecure_http: true` is set) and pin the
backend CA from `tls_ca_file` (`agent/internal/transport/http.go`). Both
backend planes refuse to start without TLS (`backend/cmd/api/main.go`,
`backend/cmd/telemetry/main.go`; TLS 1.2 minimum) and verify client
certificates against `MTLS_CA_FILE`; every authenticated route on the API
plane and every agent route on the telemetry plane passes through
`middleware.RequireMTLS`, which rejects a request without a verified peer
certificate (`backend/internal/api/middleware/require_mtls.go`). The
dashboard reaches the API plane only through `ui-proxy`, which holds a
client certificate of its own. Client certificates are
enrolled and revoked by fingerprint (`correlic-admin enroll-client-cert`,
`revoke-client-cert`, `rotate-agent-cert`); with `ALLOW_API_KEY_AUTH=false`
certificate identity is the only agent credential.

**Key types and least privilege.** API keys are 256-bit random values; only
their SHA-256 hash is stored (`backend/internal/storage/postgres_api_key_store.go`).
Keys carry a type: an *agent* key can reach the ingest, heartbeat and agent
routes and nothing else, regardless of any user row; *dashboard* keys and
sessions carry the user's role (`admin` or `member`), and every non-GET
request on configuration routes (block rules, exceptions, detection settings,
baselines, notification endpoints, AI settings, users, API keys) requires
`admin` (`backend/internal/api/middleware/auth.go`, `role_guard.go`). Every
query is scoped by organisation id. `correlic-admin bootstrap` creates the
dashboard admin and a separate agent key on first start so the agent never
holds a dashboard credential; keys are revocable with
`correlic-admin revoke-api-key`. Authenticated actions are written to the
`audit_events` table (`backend/internal/storage/audit_store.go`).

**Session cookie model.** The dashboard's Next.js server exchanges the login
for a backend session token (`POST /auth/sessions`; stored server-side as a
SHA-256 hash, 24 h TTL by default, capped at 720 h, pruned when expired) and
keeps it in the `correlic_session` cookie: `HttpOnly`, `SameSite=Lax`,
`Secure` when the request arrived over HTTPS, `Path=/`
(`ui/lib/server/session.ts`). Browser JavaScript never sees the token; the
dashboard's own server-side routes forward it as `Authorization: Bearer` and
`ui/proxy.ts` redirects every unauthenticated page to the login form. Login
is throttled per client address with a per-account backoff. Passwords are
bcrypt hashes; Google sign-in is only registered when `GOOGLE_CLIENT_ID` is
set and always verifies audience and issuer.

**Dashboard proxy on loopback.** Browsers cannot present client
certificates, so `ui-proxy/index.js` holds the backend's mTLS client
certificate on behalf of the dashboard. It binds to `127.0.0.1` unless
`BIND_HOST` says otherwise, forwards only an allowlist of path prefixes,
passes only `Authorization`, `Content-Type` and `Accept` upstream, rejects
any request without an `Authorization` header before it reaches the backend,
enforces a CORS origin allowlist and a 1 MB body limit, and never renders an
HTML error page. The dashboard itself binds to `127.0.0.1:3001` in the
systemd unit and the all-in-one image.

**Rate limiting and response hygiene.** Authenticated routes are rate
limited per caller (key hash or certificate fingerprint,
`CORRELIC_RATE_LIMIT_PER_MIN`, `backend/internal/api/middleware/ratelimit.go`);
requests without any credential are rejected by the limiter itself. Every
response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy:
no-referrer`, `Cache-Control: no-store` and, over TLS,
`Strict-Transport-Security` (`middleware/security_headers.go`). Debug
endpoints (`/debug/vars`, `/debug/pprof/*`) exist only when
`ENABLE_DEBUG_ENDPOINTS=true` and are admin-only.

**Encrypted LLM keys.** Provider keys you enter for the AI features are
encrypted with AES-256-GCM under a key derived from `LLM_ENCRYPTION_KEY`
(`backend/internal/ai/provider/settings_store.go`); the backend refuses to
start without it. Outbound webhook and Slack URLs are validated against
loopback, private, link-local and multicast ranges when configured and again
before each delivery, with redirects disabled
(`backend/internal/notification/urlcheck.go`).

**Security-first sampling.** The ingest sampler keeps always-keep and
suspicious events before it considers dropping benign ones
(`backend/internal/ingest/sampler.go`); reordering those checks is a
security bug, not a tuning choice.

**No telemetry to the project.** Nothing in Correlic calls home. The only
outbound connections the backend makes are the ones you configure: your LLM
provider, your webhook or Slack endpoints, Google's token endpoint if you
enable Google sign-in, and the optional remote key check the dashboard
performs only when you set `CORRELIC_API_URL`. The agent talks to your
backend and nowhere else.

**Agent and hook.** The agent runs as root (it loads eBPF programs) and never
kills its own PID or an AI root process (`agent/internal/enforcer/enforcer.go`).
It rate limits, deduplicates and counts what it drops
(`agent/internal/dispatch/`), and retries delivery with backoff. The
`correlic-hook` binary sends only commands, paths, URLs, names and ids, never
file contents, tool output or prompts, and fails open within a two second
budget so a backend outage never blocks a developer (`backend/docs/HOOKS.md`).

## Hardening checklist for self-hosters

1. **Keep the dashboard private.** Leave the dashboard and `ui-proxy` on
   loopback. If analysts need remote access, put a reverse proxy with TLS and
   your own authentication (or a VPN) in front of port 3001, and set
   `ALLOWED_ORIGINS` for the proxy to the exact origin you serve.
2. **Set `LLM_ENCRYPTION_KEY`** from `openssl rand -hex 32`, keep it in
   `/etc/correlic/correlic.env` (mode 0600, created by the installer) and
   back it up with the database: without it stored provider keys are
   unreadable.
3. **Rotate the first-start credentials.** The bootstrap prints the dashboard
   API key and admin password to the container log and writes them to
   `dashboard-credentials` (0600). After the first login change the admin
   password, create your own dashboard key and revoke the bootstrap key
   (`correlic-admin revoke-api-key`), delete the credentials file, and treat
   the container's log as sensitive.
4. **One credential per agent host.** Create a separate agent key (or client
   certificate) per host and revoke it when the host is decommissioned.
   Never put a dashboard key in `agent.yaml`. Prefer certificates
   (`correlic-admin enroll-client-cert`) and set `ALLOW_API_KEY_AUTH=false`
   once every agent has one.
5. **Firewall the backend.** Ports 8080 and 8081 should accept connections
   only from agent hosts and the dashboard proxy. PostgreSQL and Neo4j should
   listen on loopback or a private network only, with strong passwords.
6. **Pin and verify what you deploy.** Pin image tags to a digest, verify the
   signature and the SBOM attestation before the first run (below), and
   verify release assets with `cosign verify-blob`. Subscribe to the
   repository's releases and security advisories.
7. **Mind the all-in-one image.** It needs `--privileged --pid=host` to load
   eBPF programs, which makes the container as trusted as the host. Use it
   on hosts you would run the agent on anyway; use the separate component
   images or the installer elsewhere.
8. **Limit data retention.** Collected command lines can contain secrets.
   Configure retention (`backend/docs/DATA_RETENTION.md`) and restrict read
   access to the database and to backups.
9. **Do not enable debug endpoints in production** (`ENABLE_DEBUG_ENDPOINTS`).
10. **Keep hosts current.** The Linux agent needs a kernel 5.8+ with BTF;
    kernel updates also fix eBPF verifier issues. Windows hosts need
    command-line auditing enabled for process events to be useful.
11. **Review notifications.** Webhook URLs are secrets; use HTTPS endpoints
    with their own authentication and rotate them if a dashboard admin
    account is compromised.

## Verifying a release

Every release is built by GitHub Actions from this repository and signed with
[Sigstore](https://www.sigstore.dev/) keyless signing: the signing
certificate names the workflow file that produced the artifact and GitHub's
OIDC issuer, and the signature is recorded in the public Rekor transparency
log. No long-lived signing key exists. You need
[cosign](https://github.com/sigstore/cosign) 3.x (the bundles use the
Sigstore bundle format; cosign 2.x needs `--new-bundle-format` and may not
read them).

Identity to expect, per artifact type:

| Artifact | Signing workflow (certificate identity) |
|---|---|
| Container images on `ghcr.io/fuloxdev/*` | `https://github.com/FuloxDev/correlic/.github/workflows/release-images.yml@<ref>` |
| Linux assets (`.tar.gz`, `.deb`, `.rpm`, `SHA256SUMS-linux.txt`) | `https://github.com/FuloxDev/correlic/.github/workflows/build-linux-bundle.yml@<ref>` |
| Windows assets (`.zip`, `SHA256SUMS-windows.txt`) | `https://github.com/FuloxDev/correlic/.github/workflows/build-windows-bundle.yml@<ref>` |

`<ref>` is `refs/heads/main` for a release cut by `workflow_dispatch` (the
normal path) or `refs/tags/vX.Y.Z` for a tag-triggered rebuild. The issuer is
always `https://token.actions.githubusercontent.com`.

### Container images

```bash
IMAGE=ghcr.io/fuloxdev/correlic:v1.0.2      # any of correlic, correlic-backend, correlic-agent, correlic-ui, correlic-ui-proxy

# 1. Signature: the image index and each per-platform manifest are signed by digest.
cosign verify --output text \
  --certificate-identity-regexp '^https://github.com/FuloxDev/correlic/\.github/workflows/release-images\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE"

# 2. SBOM attestation: one SPDX 2.3 document per platform, signed and attached to the image.
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp '^https://github.com/FuloxDev/correlic/\.github/workflows/release-images\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE" | jq -r '.payload' | base64 -d | jq '.predicate.name, (.predicate.packages | length)'

# 3. Build provenance and BuildKit's own SBOM, generated by docker buildx (provenance mode=max):
docker buildx imagetools inspect "$IMAGE" --format '{{ json .Provenance }}' | jq '.["linux/amd64"].SLSA.invocation.configSource'
docker buildx imagetools inspect "$IMAGE" --format '{{ json .SBOM }}' | jq '.["linux/amd64"].SPDX.packages | length'

# 4. Pin the digest you verified:
docker buildx imagetools inspect "$IMAGE" --format '{{ .Manifest.Digest }}'
```

The provenance's `configSource` names this repository, the workflow file and
the commit; compare it with the release's tag.

### Release assets (Linux and Windows bundles)

Every asset `X` has a sibling `X.sigstore.json` (the signature bundle) and
every bundle has an SBOM `X.spdx.json`. The SBOMs are listed in the
`SHA256SUMS-*.txt` file, which is itself signed, so verifying the checksum
file covers them.

```bash
V=v1.0.2
BASE=https://github.com/FuloxDev/correlic/releases/download/$V
ID='^https://github.com/FuloxDev/correlic/\.github/workflows/build-linux-bundle\.yml@'
ISS=https://token.actions.githubusercontent.com

for f in correlic-linux-$V.tar.gz SHA256SUMS-linux.txt; do
  curl -fsSLO "$BASE/$f" && curl -fsSLO "$BASE/$f.sigstore.json"
  cosign verify-blob --bundle "$f.sigstore.json" \
    --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS" "$f"
done
sha256sum --ignore-missing -c SHA256SUMS-linux.txt
```

For the Windows bundle use `correlic-windows-$V.zip`, `SHA256SUMS-windows.txt`
and the `build-windows-bundle` identity. For `.deb` and `.rpm` files verify
the `.sigstore.json` the same way; when the maintainer has configured the
optional GPG key, the packages are additionally signed with it and
`correlic.gpg.key` ships inside `correlic-linux-repo-<version>.tar.gz` for
`apt` and `yum` (`dpkg-sig --verify`, `rpm --checksig`).

To tie an asset to the exact source commit, print the certificate from the
bundle: the `extensions` include the repository, the workflow ref and the
commit SHA.

```bash
jq -r '.verificationMaterial.certificate.rawBytes' correlic-linux-$V.tar.gz.sigstore.json \
  | base64 -d | openssl x509 -inform DER -noout -text | grep -A1 -E '1\.3\.6\.1\.4\.1\.57264\.1\.(3|5|6)'
```

(OID `.1.3` is the commit SHA, `.1.5` the repository, `.1.6` the ref.)

### Reading the SBOMs

The SBOMs are SPDX 2.3 JSON produced by [syft](https://github.com/anchore/syft).
Each bundle SBOM lists the Go modules compiled into the binaries (from the
binaries' build info), the npm packages of the dashboard and proxy, the
portable Node.js runtime and, for the Windows bundle, the PostgreSQL, Neo4j
and JRE components. The container SBOMs additionally list the OS packages of
the image.

```bash
# What is inside?
jq -r '.packages[] | "\(.name) \(.versionInfo)"' correlic-linux-v1.0.2.tar.gz.spdx.json | sort | less

# Scan the SBOM for known vulnerabilities without installing Correlic:
grype sbom:correlic-linux-v1.0.2.tar.gz.spdx.json      # or: trivy sbom correlic-linux-v1.0.2.tar.gz.spdx.json
```

## Scanning in CI

`.github/workflows/security.yml` runs CodeQL (Go and JavaScript/TypeScript),
`govulncheck` for both Go modules, a Trivy scan of the repository and a
dependency review on pull requests; `.github/workflows/scorecard.yml` runs
the OpenSSF Scorecard. Results are on the repository's Security tab.
Dependabot (`.github/dependabot.yml`) keeps Go modules, npm packages, GitHub
Actions and the base images current.
