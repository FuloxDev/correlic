// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// connect.bpf.c - eBPF program to trace outbound network connections
//
// This program attaches to the connect syscall to capture outbound
// network connections. Useful for detecting:
// - Data exfiltration attempts
// - C2 (command & control) communication
// - Lateral movement
// - Suspicious outbound connections from unexpected processes

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

// Event structure for network connections
struct connect_event {
    __u32 pid;           // Process ID
    __u32 ppid;          // Parent process ID
    __u32 uid;           // User ID
    __u32 gid;           // Group ID
    __u64 timestamp_ns;  // Nanoseconds since boot
    __u16 dport;         // Destination port (host byte order)
    __u16 family;        // Address family (AF_INET or AF_INET6)
    __u32 daddr_v4;      // IPv4 destination address
    __u8  daddr_v6[16];  // IPv6 destination address
    char comm[TASK_COMM_LEN];   // Command name
    char pcomm[TASK_COMM_LEN];  // Parent command name
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);  // 8MB buffer
} connect_events SEC(".maps");

// Tracepoint for sys_enter_connect
// This fires when any process calls connect()
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event *e;
    struct task_struct *task;
    struct sockaddr *addr;
    
    // Get sockaddr from args: connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
    addr = (struct sockaddr *)ctx->args[1];
    if (!addr) {
        return 0;
    }
    
    // Read address family
    __u16 family;
    if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) < 0) {
        return 0;
    }
    
    // Only track IPv4 and IPv6 connections
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;
    
    e->timestamp_ns = bpf_ktime_get_ns();
    e->family = family;
    
    // Get command name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Get parent info
    task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);
    
    // Read destination address based on family
    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        __u16 port_be;
        __u32 addr_be;
        
        bpf_probe_read_user(&port_be, sizeof(port_be), &sin->sin_port);
        bpf_probe_read_user(&addr_be, sizeof(addr_be), &sin->sin_addr);
        
        e->dport = bpf_ntohs(port_be);
        e->daddr_v4 = addr_be;
        __builtin_memset(e->daddr_v6, 0, sizeof(e->daddr_v6));
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        __u16 port_be;
        
        bpf_probe_read_user(&port_be, sizeof(port_be), &sin6->sin6_port);
        bpf_probe_read_user(&e->daddr_v6, sizeof(e->daddr_v6), &sin6->sin6_addr);
        
        e->dport = bpf_ntohs(port_be);
        e->daddr_v4 = 0;
    }
    
    // Submit event
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
