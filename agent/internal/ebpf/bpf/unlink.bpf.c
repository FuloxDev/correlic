// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// unlink.bpf.c - eBPF program to trace file deletions
//
// This program monitors unlink/unlinkat syscalls to detect:
// - Artifact cleanup (shell history, git objects, logs)
// - Evidence tampering
// - Suspicious file deletions by dev tools or AI agents

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256

// Event structure for file deletions
struct unlink_event {
    __u32 pid;              // Process ID
    __u32 ppid;             // Parent process ID
    __u32 uid;              // User ID
    __u64 timestamp_ns;     // Nanoseconds since boot
    __s32 dfd;              // Directory file descriptor (-1 for unlink, AT_FDCWD for cwd)
    __u32 flags;            // Flags (for unlinkat)
    char comm[TASK_COMM_LEN];     // Command name
    char pcomm[TASK_COMM_LEN];    // Parent command name
    char path[PATH_MAX_LEN];      // File path being deleted
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} unlink_events SEC(".maps");

// Sensitive paths to monitor (we'll filter in userspace for flexibility)
// But we can skip obvious noise here

// Tracepoint for sys_enter_unlink
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct unlink_event *e;
    const char *pathname;

    // Get pathname from args: unlink(const char *pathname)
    pathname = (const char *)ctx->args[0];
    if (!pathname) {
        return 0;
    }

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&unlink_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->dfd = -1;  // Regular unlink
    e->flags = 0;

    // Get command name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get parent info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);

    // Read path
    bpf_probe_read_user_str(&e->path, sizeof(e->path), pathname);

    // Submit event
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Tracepoint for sys_enter_unlinkat (more common on modern systems)
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct unlink_event *e;
    const char *pathname;

    // Get args: unlinkat(int dfd, const char *pathname, int flags)
    pathname = (const char *)ctx->args[1];
    if (!pathname) {
        return 0;
    }

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&unlink_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->dfd = (int)ctx->args[0];
    e->flags = (unsigned int)ctx->args[2];

    // Get command name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get parent info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);

    // Read path
    bpf_probe_read_user_str(&e->path, sizeof(e->path), pathname);

    // Submit event
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
