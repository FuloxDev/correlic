// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// msg.bpf.c - eBPF program to trace sendmsg/recvmsg (metadata only, no payload).
//
// Captures pid, fd, direction, and message length for protocol-aware traffic insight.
// No payload copy (privacy-safe).
//
// size: best-effort estimate from first iov only. Not guaranteed to match bytes
// sent/received (e.g. multiple iovs, partial writes). fd is for later socket
// correlation; we do not assume fd→socket is stable.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct msg_event {
	__u32 pid;
	__u32 fd;
	__u32 direction; /* 0 = send, 1 = recv */
	__u32 size;      /* best-effort from first iov; not guaranteed total */
	__u64 timestamp_ns;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} msg_events SEC(".maps");

static int submit_msg(__u32 direction, struct trace_event_raw_sys_enter *ctx)
{
	struct msg_event *e;
	__u64 fd_val = ctx->args[0];
	__u64 msg_ptr = ctx->args[1];

	e = bpf_ringbuf_reserve(&msg_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->fd = (__u32)fd_val;
	e->direction = direction;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->size = 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Best-effort: read first iov len from msghdr.msg_iov[0].iov_len (user ptr) */
	if (msg_ptr) {
		/* msghdr: msg_name(8), msg_namelen(8), msg_iov(8), ... */
		__u64 iov_ptr;
		if (bpf_probe_read_user(&iov_ptr, sizeof(iov_ptr), (void *)(msg_ptr + 16)) == 0 && iov_ptr) {
			/* iovec: iov_base(8), iov_len(8) */
			__u64 len_val;
			if (bpf_probe_read_user(&len_val, sizeof(len_val), (void *)(iov_ptr + 8)) == 0)
				e->size = (__u32)len_val;
		}
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	return submit_msg(0, ctx);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
	return submit_msg(1, ctx);
}

char LICENSE[] SEC("license") = "GPL";
