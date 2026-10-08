# eBPF Build Instructions for Correlic Agent

## Invariant: shared HostID and Dispatcher

**All eBPF runners must share the same HostID and Dispatcher instance.**
`cmd/agent/platform_linux.go` creates one dispatcher and passes the same
`hostID` and `disp` to every runner. Mixed dispatchers break correlation and
backend ingest.

## Programs

| Source (`bpf/`)   | Attach point                                   | Go runner            | Captures                                   | Config key                 |
|-------------------|------------------------------------------------|----------------------|--------------------------------------------|----------------------------|
| execsnoop.bpf.c   | tp/sched/sched_process_exec (+ sys_enter/exit_execve, execveat for argv) | runner.go | process execution, argv, exe             | `process_exec_enabled`     |
| exit.bpf.c        | raw_tracepoint/sched_process_exit              | exit_runner.go       | task exit: pid (tgid), tid, ppid, exit code | always (with exec)         |
| fork.bpf.c        | raw_tracepoint/sched_process_fork, tp/sched/sched_process_exit | fork_runner.go | process tree (tgid-keyed), lineage inheritance | `fork_monitor_enabled` |
| connect.bpf.c     | tp/syscalls/sys_enter_connect                  | network_runner.go    | outbound TCP/UDP connections               | `network_monitor_enabled`  |
| fileopen.bpf.c    | tp/syscalls/sys_enter_openat                   | file_runner.go       | credential/config file access              | `file_monitor_enabled`     |
| dns.bpf.c         | kprobe/udp_sendmsg (dport 53)                  | dns_runner.go        | DNS queries (raw question bytes)           | `dns_monitor_enabled`      |
| bind.bpf.c        | kprobe/inet_listen                             | bind_runner.go       | listening sockets                          | `bind_monitor_enabled`     |
| unlink.bpf.c      | tp/syscalls/sys_enter_unlink, sys_enter_unlinkat | unlink_runner.go   | file deletions                             | `unlink_monitor_enabled`   |
| setuid.bpf.c      | tp/syscalls/sys_enter_setuid/setgid/setresuid/setresgid | setuid_runner.go | privilege changes                     | `setuid_monitor_enabled`   |

Every program only emits raw facts. AI attribution (`ai_session_id`,
`is_ai`, `ai_type`) is added in userspace by the runners from
`internal/lineage` (whole-token pattern matching on comm/exe/argv, parent
inheritance first).

### Exit events are per task

`sched_process_exit` fires for every exiting *thread*. `exit.bpf.c` emits both
`pid` (tgid) and `tid`; `exit_runner.go` only treats `tid == pid` as a process
exit (dispatches `process_exit`, unregisters the PID). `fork.bpf.c` emits
`child_pid`/`child_tgid` the same way and the fork collector ignores threads.

### Struct layout

The C compiler pads `__u64` fields to 8 bytes. Every `*_collector.go` parser
documents the byte offsets it expects next to the struct in the `.bpf.c`;
`exit_collector_test.go` and `fork_collector_test.go` pin them. Use `pahole`
(or `bpftool btf dump file <obj>.o format c`) when changing a struct.

### CO-RE portability

Programs are compiled once against `bpf/vmlinux.h` and relocated at load time
against the running kernel's BTF. Fields whose name or layout changed across
kernels are guarded with `bpf_core_field_exists` / `bpf_core_enum_value_exists`
(see the `iov_iter` handling in `dns.bpf.c`). `objects_load_test.go` loads
every object through the verifier on the test machine (skips without BTF or
CAP_BPF; set `CORRELIC_BPF_LOAD_REQUIRED=1` to turn those skips into
failures, as CI does on runners that must load the objects).

### Architectures: amd64 and arm64

The programs are built for linux/amd64 and linux/arm64 from the same
sources and the same x86-generated `bpf/vmlinux.h`: `generate.go` runs
`bpf2go -target amd64,arm64`, which emits `<name>_x86_bpfel.{go,o}` (build
tag `386 || amd64`) and `<name>_arm64_bpfel.{go,o}` (build tag `arm64`), and
`GOARCH` picks the set that is embedded. CO-RE makes the shared `vmlinux.h`
work: every kernel-struct access (task_struct, sock, msghdr, iov_iter,
tracepoint contexts, ...) is relocated by field name against the running
kernel's BTF, whatever its architecture. The one architecture-specific piece
is the register file that kprobe programs read their arguments from:

- `bpf/arch_arm64.h` declares `struct user_pt_regs` (x0..x30, sp, pc,
  pstate: the arm64 kernel's user ABI and the first member of its
  `struct pt_regs`) for `-target arm64`, because libbpf's `bpf_tracing.h`
  implements `PT_REGS_PARMn()` / `BPF_KPROBE()` on arm64 as
  `((const struct user_pt_regs *)ctx)->regs[n-1]` and the x86 `vmlinux.h`
  has no such type. It is declared outside the `preserve_access_index`
  pragma on purpose: those offsets are ABI constants, nothing to relocate.
  Include it after `vmlinux.h` and before `<bpf/bpf_tracing.h>` in every
  program that uses `PT_REGS_*` or `BPF_KPROBE` (`dns.bpf.c`,
  `bind.bpf.c`); it is empty for other targets. Do not use the `*_CORE` or
  `*_SYSCALL` flavours of the `PT_REGS_*` macros: they need the real arm64
  `struct pt_regs`.
- Tracepoint and raw-tracepoint programs need nothing: syscall tracepoints
  read `ctx->args[]`, which is architecture independent.
- arm64 uses the asm-generic syscall table, which has no `unlink(2)` (libc
  implements `unlink()` with `unlinkat`), so the `sys_enter_unlink`
  tracepoint does not exist there. `unlink_collector.go` treats that as
  "not on this architecture" and monitors `unlinkat` only. `open(2)` is
  likewise absent but was never hooked (`fileopen.bpf.c` uses `openat`).

CI builds, vets and tests the agent on an `ubuntu-24.04-arm` runner
(`agent-linux-arm64` in `.github/workflows/ci.yml`) and loads the arm64
objects into that kernel with `CORRELIC_BPF_LOAD_REQUIRED=1`.

## Prerequisites

- Go 1.26+
- clang/LLVM (18+ known good) and `libbpf` headers (`bpf/bpf_helpers.h`,
  `bpf/bpf_tracing.h`, `bpf/bpf_core_read.h`, `bpf/bpf_endian.h`)
- A BTF-enabled kernel (`/sys/kernel/btf/vmlinux`) for `vmlinux.h` and for tests

The generated `*_x86_bpfel.go` / `*_arm64_bpfel.go` and `.o` files are
git-ignored (`agent/.gitignore` and the root `.gitignore` match `*_bpfel.*`);
`go build` needs them, so run `go generate` after a fresh clone and after any
`.bpf.c` change.

## Step 1: Generate vmlinux.h

Only needed when adding fields that the checked-in header lacks:

```bash
cd agent
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
```

If `bpftool` is not installed:
```bash
sudo apt install linux-tools-common linux-tools-$(uname -r)
```

## Step 2: Install Go dependencies

```bash
cd agent
go mod tidy
```

## Step 3: Generate eBPF Go bindings

```bash
go generate ./internal/ebpf/...
# libbpf headers outside the default include path:
CPATH=/path/to/libbpf/include go generate ./internal/ebpf/...
```

This compiles every `bpf/*.bpf.c` with `clang -O2 -g -Wall -Werror -target bpf`
via `bpf2go`, once per supported architecture (`-target amd64,arm64`), and
writes `<name>_x86_bpfel.go` + `.o` and `<name>_arm64_bpfel.go` + `.o` next
to the Go code. One `go generate` on any host serves native and cross builds.

## Step 4: Build and Test

```bash
go build ./...
go vet ./...
go test -race ./...           # includes the kernel load test when run with CAP_BPF
GOOS=linux GOARCH=arm64 go build ./... && GOOS=linux GOARCH=arm64 go vet ./...   # cross build
sudo ./correlic-agent --config /etc/correlic/agent.yaml
```

`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o correlic-agent ./cmd/agent`
produces the arm64 agent from an x86_64 host (and vice versa); the eBPF
objects for both architectures are already in place after `go generate`.

A live check without a backend: point `backend_url`/`telemetry_url` at an
unreachable https address, enable the monitors, start the agent and confirm
the collectors attach, the delivery failures are logged at WARN once per
minute per component, and SIGTERM exits with "shutdown complete".

## Troubleshooting

### "vmlinux.h: No such file"
Run Step 1 to generate it.

### "bpf/bpf_helpers.h: No such file"
Install libbpf headers or point `CPATH` at them (Step 3).

### "operation not permitted"
Run the agent as root or with CAP_BPF + CAP_PERFMON.

### "unknown type name 'struct trace_event_raw_sched_process_exec'"
Regenerate vmlinux.h - it may be from a different kernel.

### "unknown type name 'struct user_pt_regs'" (arm64 target)
A kprobe program uses `PT_REGS_*` / `BPF_KPROBE` without including
`arch_arm64.h` before `<bpf/bpf_tracing.h>`. See "Architectures" above.

### Verifier errors
Usually a stack overflow (512 B limit), an unbounded loop or a CO-RE field
that does not exist on the running kernel. `go test -run TestLoadBPFObjects -v ./internal/ebpf/`
prints the verifier log for the failing program.

### DNS kprobe cannot be created
`kprobe/udp_sendmsg` needs tracefs (`mount -t tracefs nodev /sys/kernel/tracing`)
and a kernel that exports the symbol; the other collectors keep running.
