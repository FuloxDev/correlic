# Contributing

Thanks for helping. The repository is one tree with four buildable components;
each has its own toolchain notes in a `CLAUDE.md` next to its code.

## Building and testing

```bash
# backend (Go 1.24+)
cd backend && go build ./... && go vet ./... && go test ./...

# agent (Go 1.25+, clang/llvm/libbpf-dev for the eBPF objects)
cd agent && go generate ./internal/ebpf/... && go build ./... && go test ./...

# dashboard and proxy (Node 20+)
cd ui && npm ci && npx tsc --noEmit && npm run lint && npm run build
cd ui-proxy && npm ci && node --check index.js
```

CI runs the same commands on every pull request (`.github/workflows/ci.yml`).

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

## Reporting bugs

Use the issue templates. For security problems see `SECURITY.md`.
