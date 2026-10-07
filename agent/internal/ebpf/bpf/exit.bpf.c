// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// exit.bpf.c - eBPF program to trace process exit (sched_process_exit).
// Phase 20: exec lifecycle modeling. No maps except ringbuf; no correlation in BPF.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct exit_event {
	__u32 pid;
	__u32 ppid;
	__u32 exit_code;  // task->exit_code >> 8 (user-visible exit code)
	__u64 timestamp_ns;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} exit_events SEC(".maps");

// sched_process_exit: (struct task_struct *p, int exit_code)
SEC("raw_tracepoint/sched_process_exit")
int handle_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct exit_event *e;
	struct task_struct *task;
	int exit_code;

	if (ctx->args[0] == 0)
		return 0;
	task = (struct task_struct *)ctx->args[0];
	exit_code = (int)(long)ctx->args[1];

	e = bpf_ringbuf_reserve(&exit_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = BPF_CORE_READ(task, tgid);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = exit_code >> 8;  // user-visible exit code (LSB is signal)
	e->timestamp_ns = bpf_ktime_get_ns();
	
	// Use bpf_get_current_comm() instead of bpf_core_read() for safe string reading
	// bpf_core_read() reads raw kernel memory which may contain garbage/binary data
	// bpf_get_current_comm() is the correct BPF helper for reading process names
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
