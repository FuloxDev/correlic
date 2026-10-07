// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// dns.bpf.c - eBPF program to trace DNS queries
//
// This program monitors DNS traffic for:
// - DGA (Domain Generation Algorithm) detection
// - Data exfiltration via DNS tunneling
// - C2 domain lookups
//
// Uses kprobe/udp_sendmsg to capture ALL UDP sends to port 53,
// including send() on connected sockets (glibc resolver path).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define MAX_DNS_NAME 128
#define DNS_PORT 53
#define DNS_HDR_LEN 12

// Event structure for DNS queries
struct dns_event {
    __u32 pid;            // Process ID
    __u32 ppid;           // Parent process ID
    __u32 uid;            // User ID
    __u64 timestamp_ns;   // Nanoseconds since boot
    __u16 qtype;          // Query type (A=1, AAAA=28, etc.)
    __u16 qclass;         // Query class (IN=1)
    __u32 dst_ip;         // DNS server IP
    char comm[TASK_COMM_LEN];      // Command name
    char domain[MAX_DNS_NAME];     // Raw DNS question bytes (QNAME + QTYPE + QCLASS)
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);  // 2MB buffer
} dns_events SEC(".maps");

// kprobe on udp_sendmsg catches ALL UDP sends (sendto, send, sendmsg, write)
// regardless of whether the socket is connected or not.
// Prototype: int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("kprobe/udp_sendmsg")
int trace_dns_udp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!sk || !msg)
        return 0;

    // Filter for DNS: check destination port == 53
    // For connected sockets, sk_dport is set by connect().
    // For unconnected sendto(), the kernel sets inet->inet_dport before
    // calling udp_sendmsg, so sk_dport is populated either way.
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (bpf_ntohs(dport) != DNS_PORT)
        return 0;

    // Reserve ring buffer space
    struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;

    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    // DNS server IP (network byte order)
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    // Read DNS payload from the iovec.
    // msg->msg_iter contains the data; we read the first iov segment.
    __builtin_memset(e->domain, 0, sizeof(e->domain));
    e->qtype = 0;
    e->qclass = 0;

    struct iov_iter *iter = &msg->msg_iter;
    const struct iovec *iov;
    void *iov_base;
    size_t iov_len;

    // Read iov pointer from the iter union (ITER_IOVEC path)
    bpf_probe_read_kernel(&iov, sizeof(iov), &iter->__iov);
    if (iov) {
        bpf_probe_read_kernel(&iov_base, sizeof(iov_base), &iov->iov_base);
        bpf_probe_read_kernel(&iov_len, sizeof(iov_len), &iov->iov_len);

        // DNS header is 12 bytes, then question section follows.
        // Copy raw question bytes; parse in userspace for correctness.
        if (iov_base && iov_len > DNS_HDR_LEN) {
            __u64 read_len = iov_len - DNS_HDR_LEN;
            if (read_len > sizeof(e->domain) - 1)
                read_len = sizeof(e->domain) - 1;
            if (read_len > 0 && read_len <= sizeof(e->domain) - 1) {
                bpf_probe_read_user(e->domain, read_len,
                                    (const void *)iov_base + DNS_HDR_LEN);
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
