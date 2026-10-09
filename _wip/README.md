# Work in progress (paused 2026-10-09)

Uncommitted, unfinished work from three parallel streams, saved as patches so
nothing is lost between sessions. Nothing here is built, tested or shipped;
`go build ./...` skips this directory. Delete the directory once the patches
have been applied and finished.

| Patch | Stream | State when paused |
|---|---|---|
| `demo.patch` | `correlic-admin simulate`, `scripts/demo/`, `scripts/ci/` | simulate command and test drafted; checklist card, screenshots, GIF and `integration.yml` not started |
| `deploy.patch` | `backend/internal/metrics/` | Prometheus metrics package drafted; wiring into both planes, version-skew warning and OPERATIONS.md not done |
| `bench.patch` | `scripts/bench/`, CHANGELOG entry | benchmark scripts drafted; results not captured, BENCHMARKS.md not written |

Resume with `git apply _wip/<name>.patch` on a branch from `main`, then
continue from the stream's brief in the session transcript.
