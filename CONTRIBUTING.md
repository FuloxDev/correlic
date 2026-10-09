# Contributing

Thanks for helping. The repository is one tree with four buildable components;
each has its own toolchain notes in a `CLAUDE.md` next to its code.

## Building and testing

```bash
# backend (Go 1.26+)
cd backend && go build ./... && go vet ./... && go test ./...

# agent (Go 1.26+, clang/llvm/libbpf-dev for the eBPF objects)
cd agent && go generate ./internal/ebpf/... && go build ./... && go test ./...

# dashboard and proxy (Node 22+)
cd ui && npm ci && npx tsc --noEmit && npm run lint && npm run build
cd ui-proxy && npm ci && node --check index.js
```

CI runs the same commands on every pull request (`.github/workflows/ci.yml`).
`.github/workflows/security.yml` adds CodeQL, `govulncheck`, a Trivy scan and
a dependency review; only `govulncheck` and the dependency review can fail a
pull request, and only on a known vulnerability in a dependency.

## Pull requests

- Keep a pull request to one change. Describe what breaks without it.
- Add or update a test when the change touches detection rules, the ingest
  pipeline, authentication, or the agent's parsers.
- Do not commit generated eBPF objects (`*_bpfel.go`), credentials, certificates
  or `agent.yaml` files; `.gitignore` already covers them.
- Run `gofmt` on Go changes and `npm run lint` on dashboard changes.

## Design docs

`backend/docs/SYSTEM_REFERENCE.md` is the entry point; the detection engine,
correlation, incident and AI layers each have their own document in
`backend/docs/`.

## Security-relevant changes

Read [`backend/docs/THREAT_MODEL.md`](backend/docs/THREAT_MODEL.md) before
touching the ingest path, authentication, the agent's enforcer, the hook or
a release workflow; it says which code paths carry which guarantee. Changes
to `.github/workflows/` need a code owner review (`.github/CODEOWNERS`) and,
for the release workflows, a dry run as described in
[`backend/docs/RELEASE_PROCESS.md`](backend/docs/RELEASE_PROCESS.md).

## Reporting bugs

Use the issue templates. For security problems see [`SECURITY.md`](SECURITY.md).
