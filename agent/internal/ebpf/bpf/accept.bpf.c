// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// accept.bpf.c - eBPF program to trace inbound network connections (accept/accept4)
//
// On sys_enter we store the sockaddr* (output buffer) in a per-pid map; on sys_exit
// the kernel has filled it, so we read client IP/port and submit to ringbuf.
//
// Error handling: we do NOT emit on failed accept. ret < 0 (kernel -errno) or fd < 0
// → skip submit, only cleanup map. This avoids phantom inbound connections.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

struct accept_event {
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u64 timestamp_ns;
	__u16 family;
	__u16 client_port;
	__u32 client_addr_v4;
	__u8  client_addr_v6[16];
	char comm[TASK_COMM_LEN];
	char pcomm[TASK_COMM_LEN];
};

/* pid_tgid -> sockaddr* (stored on enter, read on exit) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, __u64);
} accept_addr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} accept_events SEC(".maps");

static int submit_from_addr(void *addr_ptr)
{
	struct sockaddr *addr = (struct sockaddr *)addr_ptr;
	struct accept_event *e;
	struct task_struct *task;
	__u16 family;

	if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) < 0)
		return 0;

	/* Only IPv4 and IPv6. Unknown family → do not emit (no garbage or mislabel). */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	e = bpf_ringbuf_reserve(&accept_events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->gid = bpf_get_current_uid_gid() >> 32;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->family = family;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	e->ppid = BPF_CORE_READ(parent, tgid);
	bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		__u16 port_be;
		__u32 addr_be;

		bpf_probe_read_user(&port_be, sizeof(port_be), &sin->sin_port);
		bpf_probe_read_user(&addr_be, sizeof(addr_be), &sin->sin_addr);

		e->client_port = bpf_ntohs(port_be);
		e->client_addr_v4 = addr_be;
		__builtin_memset(e->client_addr_v6, 0, sizeof(e->client_addr_v6));
	} else {
		/* AF_INET6: store raw bytes (no string formatting in BPF). */
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		__u16 port_be;

		bpf_probe_read_user(&port_be, sizeof(port_be), &sin6->sin6_port);
		bpf_probe_read_user(&e->client_addr_v6, sizeof(e->client_addr_v6), &sin6->sin6_addr);

		e->client_port = bpf_ntohs(port_be);
		e->client_addr_v4 = 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

static void accept_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 addr = ctx->args[1];
	if (addr)
		bpf_map_update_elem(&accept_addr_map, &pid_tgid, &addr, BPF_ANY);
}

static void accept_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *addr_ptr;

	if (ctx->ret < 0)
		goto cleanup;

	addr_ptr = bpf_map_lookup_elem(&accept_addr_map, &pid_tgid);
	if (!addr_ptr)
		return;

	submit_from_addr((void *)*addr_ptr);

cleanup:
	bpf_map_delete_elem(&accept_addr_map, &pid_tgid);
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx)
{
	accept_enter(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
	accept_exit(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4_enter(struct trace_event_raw_sys_enter *ctx)
{
	accept_enter(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept4_exit(struct trace_event_raw_sys_exit *ctx)
{
	accept_exit(ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
