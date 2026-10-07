// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// setuid.bpf.c - eBPF program to trace privilege escalation attempts
//
// This program monitors setuid/setgid/setresuid/setresgid syscalls to detect:
// - Privilege escalation (user -> root)
// - Privilege dropping (root -> user)
// - Suspicious UID/GID changes by dev tools

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

// Event structure for privilege changes
struct setuid_event {
    __u32 pid;              // Process ID
    __u32 ppid;             // Parent process ID
    __u32 old_uid;          // Original UID
    __u32 old_euid;         // Original effective UID
    __u32 new_uid;          // Target UID (from syscall arg)
    __u32 new_euid;         // Target effective UID (for setresuid)
    __u32 new_suid;         // Target saved UID (for setresuid)
    __u64 timestamp_ns;     // Nanoseconds since boot
    __u8 syscall_type;      // 0=setuid, 1=setgid, 2=setresuid, 3=setresgid
    char comm[TASK_COMM_LEN];     // Command name
    char pcomm[TASK_COMM_LEN];    // Parent command name
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} setuid_events SEC(".maps");

// Helper to fill common event fields
static __always_inline void fill_event_common(struct setuid_event *e, __u8 syscall_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->old_uid = uid_gid & 0xFFFFFFFF;
    e->old_euid = uid_gid & 0xFFFFFFFF;  // Simplified - real euid would need task_struct

    e->timestamp_ns = bpf_ktime_get_ns();
    e->syscall_type = syscall_type;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get parent info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);
}

// Tracepoint for sys_enter_setuid
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct setuid_event *e;

    e = bpf_ringbuf_reserve(&setuid_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_event_common(e, 0);  // syscall_type = 0 for setuid

    // setuid(uid_t uid)
    e->new_uid = (unsigned int)ctx->args[0];
    e->new_euid = e->new_uid;
    e->new_suid = e->new_uid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint for sys_enter_setgid
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    struct setuid_event *e;

    e = bpf_ringbuf_reserve(&setuid_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_event_common(e, 1);  // syscall_type = 1 for setgid

    // setgid(gid_t gid)
    e->new_uid = (unsigned int)ctx->args[0];
    e->new_euid = e->new_uid;
    e->new_suid = e->new_uid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint for sys_enter_setresuid (most commonly used)
SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    struct setuid_event *e;

    e = bpf_ringbuf_reserve(&setuid_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_event_common(e, 2);  // syscall_type = 2 for setresuid

    // setresuid(uid_t ruid, uid_t euid, uid_t suid)
    e->new_uid = (unsigned int)ctx->args[0];   // real UID
    e->new_euid = (unsigned int)ctx->args[1];  // effective UID
    e->new_suid = (unsigned int)ctx->args[2];  // saved UID

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint for sys_enter_setresgid
SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid(struct trace_event_raw_sys_enter *ctx)
{
    struct setuid_event *e;

    e = bpf_ringbuf_reserve(&setuid_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_event_common(e, 3);  // syscall_type = 3 for setresgid

    // setresgid(gid_t rgid, gid_t egid, gid_t sgid)
    e->new_uid = (unsigned int)ctx->args[0];   // real GID
    e->new_euid = (unsigned int)ctx->args[1];  // effective GID
    e->new_suid = (unsigned int)ctx->args[2];  // saved GID

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
