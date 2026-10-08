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
CAP_BPF).

## Prerequisites

- Go 1.26+
- clang/LLVM (18+ known good) and `libbpf` headers (`bpf/bpf_helpers.h`,
  `bpf/bpf_tracing.h`, `bpf/bpf_core_read.h`, `bpf/bpf_endian.h`)
- A BTF-enabled kernel (`/sys/kernel/btf/vmlinux`) for `vmlinux.h` and for tests

The generated `*_x86_bpfel.go` / `*.o` files are git-ignored; `go build` needs
them, so run `go generate` after a fresh clone and after any `.bpf.c` change.

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
via `bpf2go` and writes `<name>_x86_bpfel.go` + `.o` next to the Go code.

## Step 4: Build and Test

```bash
go build ./...
go vet ./...
go test -race ./...           # includes the kernel load test when run with CAP_BPF
sudo ./correlic-agent --config /etc/correlic/agent.yaml
```

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

### Verifier errors
Usually a stack overflow (512 B limit), an unbounded loop or a CO-RE field
that does not exist on the running kernel. `go test -run TestLoadBPFObjects -v ./internal/ebpf/`
prints the verifier log for the failing program.

### DNS kprobe cannot be created
`kprobe/udp_sendmsg` needs tracefs (`mount -t tracefs nodev /sys/kernel/tracing`)
and a kernel that exports the symbol; the other collectors keep running.
