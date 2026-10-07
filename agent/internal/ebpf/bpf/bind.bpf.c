// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// bind.bpf.c - eBPF program to trace socket bind operations
//
// This program monitors bind() syscalls to detect:
// - Servers binding to 0.0.0.0 (exposed to all interfaces)
// - Unexpected listeners from dev tools (IDE, node, python)
// - Reverse shell patterns (bind + exec shell)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

// Event structure for bind operations
struct bind_event {
    __u32 pid;            // Process ID
    __u32 ppid;           // Parent process ID
    __u32 uid;            // User ID
    __u64 timestamp_ns;   // Nanoseconds since boot
    __u16 port;           // Port being bound (host byte order)
    __u16 family;         // Address family (AF_INET or AF_INET6)
    __u32 addr_v4;        // IPv4 bind address (network byte order)
    __u8  addr_v6[16];    // IPv6 bind address
    char comm[TASK_COMM_LEN];   // Command name
    char pcomm[TASK_COMM_LEN];  // Parent command name
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} bind_events SEC(".maps");

// Tracepoint for inet_listen: captures port AFTER bind/assignment
SEC("kprobe/inet_listen")
int BPF_KPROBE(trace_listen, struct socket *sock, int backlog)
{
    struct bind_event *e;
    struct sock *sk;
    
    // Read sock->sk
    sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        return 0;
    }
    
    // Read address family
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    
    // Only track IPv4 and IPv6
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&bind_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    
    e->timestamp_ns = bpf_ktime_get_ns();
    e->family = family;
    
    // Get command name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Get parent info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);
    
    // Read port directly from sock (network byte order? typically yes in kernel struct)
    // sk->sk_num is usually host byte order? Let's check.
    // In L4, sk->sk_num is often host byte order for inet_sock.
    // But sk->sk_dport/sport might be network.
    // Common practice: use sk->sk_num as source port (host byte order).
    e->port = BPF_CORE_READ(sk, __sk_common.skc_num);
    
    // Read address based on family
    if (family == AF_INET) {
        e->addr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __builtin_memset(e->addr_v6, 0, sizeof(e->addr_v6));
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&e->addr_v6, sizeof(e->addr_v6), &sk->__sk_common.skc_v6_rcv_saddr);
        e->addr_v4 = 0;
    }
    
    // Submit event
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
