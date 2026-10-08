// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// fork.bpf.c - eBPF program to trace process creation for tree visualization
//
// This program monitors fork/clone/vfork to build process trees:
// - Track parent-child relationships (keyed by thread group id in userspace)
// - Capture process creation time
// - Enable correlation with other events
//
// Both the task id (pid) and the thread group id (tgid) are emitted for the
// parent and the child. A new thread has child_pid != child_tgid; userspace
// ignores those so only real processes enter the tree.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

// Event structure for process creation / exit
struct fork_event {
    __u32 parent_pid;       // Parent task id (the forking thread)
    __u32 parent_tgid;      // Parent thread group id (the process)
    __u32 child_pid;        // Child task id
    __u32 child_tgid;       // Child thread group id
    __u32 uid;              // User ID
    __u64 timestamp_ns;     // Nanoseconds since boot
    __u64 clone_flags;      // 0 for fork events, ~0 for exit events
    char parent_comm[TASK_COMM_LEN];  // Parent command name
    char child_comm[TASK_COMM_LEN];   // Child command name (initially same as parent)
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} fork_events SEC(".maps");

// Raw tracepoint for sched_process_fork: avoids typed tracepoint context so we
// don't depend on trace_event_raw_sched_process_fork in kernel BTF (which can
// cause "invalid func" CO-RE failures). Args are (parent task_struct *, child task_struct *).
SEC("raw_tracepoint/sched_process_fork")
int trace_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct fork_event *e;
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    e = bpf_ringbuf_reserve(&fork_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->parent_pid = BPF_CORE_READ(parent, pid);
    e->child_pid = BPF_CORE_READ(child, pid);
    e->parent_tgid = BPF_CORE_READ(parent, tgid);
    e->child_tgid = BPF_CORE_READ(child, tgid);

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->clone_flags = 0;

    // Read parent comm from parent task struct (not current process!)
    // bpf_get_current_comm() would read the CHILD process in fork tracepoint
    // Use bpf_probe_read_kernel_str to safely read from parent task_struct
    bpf_probe_read_kernel_str(&e->parent_comm, sizeof(e->parent_comm), &parent->comm);

    // Read child comm from child task struct
    bpf_probe_read_kernel_str(&e->child_comm, sizeof(e->child_comm), &child->comm);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Track task exit so the userspace tree can forget finished processes.
// child_pid is the exiting task id and child_tgid its process; userspace only
// removes a tree entry when the thread group leader exits (child_pid == child_tgid).
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct fork_event *e;

    e = bpf_ringbuf_reserve(&fork_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // For exit, we set parent = 0 to indicate this is an exit event
    e->parent_pid = 0;
    e->parent_tgid = 0;

    // The exiting task
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->child_pid = (__u32)pid_tgid;
    e->child_tgid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->clone_flags = 0xFFFFFFFFFFFFFFFF;  // Special marker for exit

    bpf_get_current_comm(&e->child_comm, sizeof(e->child_comm));
    __builtin_memset(e->parent_comm, 0, sizeof(e->parent_comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
