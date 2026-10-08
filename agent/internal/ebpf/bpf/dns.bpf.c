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
//
// Portability: the layout of struct iov_iter changed several times.
//   - < 6.4: the iovec pointer is `iov`
//   - >= 6.4: it is `__iov`
//   - >= 6.0: single-buffer sends use ITER_UBUF with the user pointer in
//     `ubuf` and the length in `count` (6.4+ also aliases this as
//     `__ubuf_iovec`)
// All accesses are CO-RE relocated and guarded with bpf_core_field_exists /
// bpf_core_enum_value_exists so one object loads on every supported kernel.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define MAX_DNS_NAME 128
#define DNS_PORT 53
#define DNS_HDR_LEN 12

// CO-RE "flavour" of struct iov_iter for kernels before 6.4, where the iovec
// pointer field is named `iov`. libbpf/cilium strip the ___old suffix when
// matching against the running kernel's BTF, so the field access below is
// relocated (or reported as missing) like any other.
struct iov_iter___old {
    const struct iovec *iov;
} __attribute__((preserve_access_index));

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

// first_segment resolves the user pointer and length of the first data
// segment of msg->msg_iter. Returns 0 on success, -1 when the iterator type
// is not one we can read (kvec/bvec/xarray: kernel-internal sends).
static __always_inline int first_segment(struct iov_iter *iter, void **base, __u64 *len)
{
    int is_ubuf = 0;
    int is_iovec = 1;

    // iter_type (u8) exists since 5.14; older kernels keep flags in `type`
    // and only have the iovec layout for sendmsg, so assume ITER_IOVEC there.
    if (bpf_core_field_exists(iter->iter_type)) {
        __u8 type = BPF_CORE_READ(iter, iter_type);
        if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF))
            is_ubuf = (type == bpf_core_enum_value(enum iter_type, ITER_UBUF));
        is_iovec = (type == bpf_core_enum_value(enum iter_type, ITER_IOVEC));
    }

    if (is_ubuf) {
        // Single user buffer: pointer in `ubuf`, length in `count`.
        if (!bpf_core_field_exists(iter->ubuf))
            return -1;
        *base = BPF_CORE_READ(iter, ubuf);
        *len = BPF_CORE_READ(iter, count);
        return 0;
    }

    if (!is_iovec)
        return -1;

    const struct iovec *iov = NULL;
    if (bpf_core_field_exists(iter->__iov)) {
        iov = BPF_CORE_READ(iter, __iov);
    } else {
        struct iov_iter___old *old = (struct iov_iter___old *)iter;
        if (bpf_core_field_exists(old->iov))
            iov = BPF_CORE_READ(old, iov);
    }
    if (!iov)
        return -1;

    // The iovec array lives in kernel memory (copied in by the syscall layer).
    void *iov_base = NULL;
    __u64 iov_len = 0;
    bpf_probe_read_kernel(&iov_base, sizeof(iov_base), &iov->iov_base);
    bpf_probe_read_kernel(&iov_len, sizeof(iov_len), &iov->iov_len);
    *base = iov_base;
    *len = iov_len;
    return 0;
}

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

    // Read DNS payload from the first data segment of the message.
    __builtin_memset(e->domain, 0, sizeof(e->domain));
    e->qtype = 0;
    e->qclass = 0;

    void *base = NULL;
    __u64 len = 0;
    if (first_segment(&msg->msg_iter, &base, &len) == 0 && base && len > DNS_HDR_LEN) {
        // DNS header is 12 bytes, then question section follows.
        // Copy raw question bytes; parse in userspace for correctness.
        __u64 read_len = len - DNS_HDR_LEN;
        if (read_len > sizeof(e->domain) - 1)
            read_len = sizeof(e->domain) - 1;
        if (read_len > 0 && read_len <= sizeof(e->domain) - 1) {
            bpf_probe_read_user(e->domain, read_len,
                                (const void *)base + DNS_HDR_LEN);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
