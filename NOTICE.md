# Third-party notices

Correlic itself is MIT licensed (see `LICENSE`). The pieces below are either
included in this repository under their own terms or redistributed, unmodified,
inside the install bundles and the all-in-one container image.

## In this repository

| Path | License | Notes |
|---|---|---|
| `agent/internal/ebpf/bpf/*.bpf.c` | GPL-2.0 OR BSD-3-Clause | eBPF programs loaded into the Linux kernel. They declare `GPL` in their license section because they use GPL-only kernel helpers. |
| `agent/internal/ebpf/bpf/vmlinux.h` | Generated from Linux kernel BTF | Type definitions produced with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`; regenerate for your kernel if needed. |
| `paper-supplementary/` | CC BY 4.0 | Rule set, chain patterns and never-baseline list accompanying the paper. |

## Redistributed in the all-in-one image and install bundles

| Component | License | Where |
|---|---|---|
| Neo4j Community Edition 5 | GPL-3.0 | all-in-one image (apt package), Windows bundle (zip). Runs as a separate process reached over Bolt; source is available from https://github.com/neo4j/neo4j |
| PostgreSQL 16 | PostgreSQL License | all-in-one image, Windows bundle |
| Node.js 24 | MIT (plus bundled components, see its LICENSE) | all-in-one image, Linux and Windows bundles |
| Eclipse Temurin JRE 17 | GPL-2.0 with Classpath Exception | Windows bundle |
| libbpf headers | LGPL-2.1 OR BSD-2-Clause | used at build time to compile the eBPF programs |

Go module and npm dependencies are permissively licensed (MIT, BSD, Apache-2.0,
ISC); see `backend/go.mod`, `agent/go.mod` and the `package-lock.json` files
for the exact set.
