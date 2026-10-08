// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// exit.bpf.c - eBPF program to trace task exit (sched_process_exit).
// Phase 20: exec lifecycle modeling. No maps except ringbuf; no correlation in BPF.
//
// sched_process_exit fires for every exiting *task*, i.e. for each thread of
// a multithreaded process. Both the thread group id (pid) and the thread id
// (tid) are emitted so userspace can treat only tid == pid as a process exit.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct exit_event {
	__u32 pid;        // thread group id (process id)
	__u32 tid;        // thread id; == pid for the thread group leader
	__u32 ppid;       // parent thread group id
	__u32 exit_code;  // task->exit_code >> 8 (user-visible exit status)
	__u64 timestamp_ns;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} exit_events SEC(".maps");

// sched_process_exit: (struct task_struct *p[, bool group_dead])
SEC("raw_tracepoint/sched_process_exit")
int handle_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct exit_event *e;
	struct task_struct *task;

	if (ctx->args[0] == 0)
		return 0;
	task = (struct task_struct *)ctx->args[0];

	e = bpf_ringbuf_reserve(&exit_events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// The tracepoint carries no exit code; read it from the task. The low
	// byte is the terminating signal, the next byte the exit status.
	e->exit_code = (__u32)(BPF_CORE_READ(task, exit_code) >> 8);
	e->timestamp_ns = bpf_ktime_get_ns();

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
