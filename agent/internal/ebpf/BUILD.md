# eBPF Build Instructions for Correlic Agent

## Invariant: shared HostID and Dispatcher

**All eBPF runners must share the same HostID and Dispatcher instance.**  
If you start the exec Runner, AcceptRunner, MsgRunner, etc., pass the same `hostID` and `disp` to each. Mixed dispatchers break correlation and backend ingest.

## Prerequisites

Your system already has the required tools:
- ✅ Kernel 6.12 (BTF-enabled)
- ✅ Clang 21
- ✅ LLVM 21

## Step 1: Generate vmlinux.h

This file contains kernel type definitions. Run once per kernel version:

```bash
cd /home/fulox/tmp/Correlic-agent
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
```

If `bpftool` is not installed:
```bash
sudo apt install linux-tools-common linux-tools-$(uname -r)
```

## Step 2: Install Go dependencies

```bash
cd /home/fulox/tmp/Correlic-agent
go mod tidy
```

## Step 3: Generate eBPF Go bindings

```bash
go generate ./internal/ebpf/...
```

This compiles all `*.bpf.c` programs and generates Go bindings, including:
- `execsnoop_*` - process exec
- `connect_*` - outbound connections
- `accept_*` - inbound connections (accept/accept4)
- `msg_*` - sendmsg/recvmsg metadata (no payload)

## Step 4: Build and Test

```bash
go build ./...
# If you have a main that starts collectors (e.g. cmd/agent):
# Start AcceptRunner and MsgRunner alongside the exec Runner, with the same HostID and Dispatcher.
sudo ./agent  # Must run as root for eBPF
```

## Troubleshooting

### "vmlinux.h: No such file"
Run Step 1 to generate it.

### "operation not permitted"
Run the agent with `sudo`.

### "unknown type name 'struct trace_event_raw_sched_process_exec'"
Regenerate vmlinux.h - it may be from a different kernel.
