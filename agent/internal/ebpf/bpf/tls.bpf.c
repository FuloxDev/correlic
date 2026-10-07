// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// tls.bpf.c - Trace OpenSSL SSL_read/SSL_write for plaintext capture (Uprobes)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_DATA_SIZE 4096
#define TASK_COMM_LEN 16

// TLS Event identifying a Read or Write operation
struct tls_event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u64 timestamp_ns;
    __u32 len;
    __u32 direction; // 0 = Write (Send), 1 = Read (Recv)
    char comm[TASK_COMM_LEN];
    __u8 data[MAX_DATA_SIZE];
};

// Filter: PIDs that are flagged as "AI Context"
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u8);
} ai_pids SEC(".maps");

// Ringbuffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB buffer for payload data
} tls_events SEC(".maps");

// Context for SSL_read (to correlate entry and exit)
struct ssl_read_ctx {
    __u64 buffer_addr;
};

// Track active SSL_read calls: PID_TGID -> Buffer Address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct ssl_read_ctx);
} active_ssl_reads SEC(".maps");

// Force BTF generation for tls_event
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tls_event);
} tls_event_dummy SEC(".maps");

// Helper to check if PID is AI (with lazy inheritance)
static __always_inline bool is_ai_process(__u32 pid) {
    u8 *val = bpf_map_lookup_elem(&ai_pids, &pid);
    if (val) return true;

    // Check parent (lazy inheritance)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    __u32 ppid;
    
    // Read parent pointer and PID
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);

    // If parent is AI, child is AI
    val = bpf_map_lookup_elem(&ai_pids, &ppid);
    if (val) {
        __u8 one = 1;
        bpf_map_update_elem(&ai_pids, &pid, &one, BPF_ANY);
        return true;
    }

    return false;
}

// SSL_write(ssl, buf, num)
SEC("uprobe/SSL_write")
int probe_SSL_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 1. Filter: Only capture if PID is known AI
    if (!is_ai_process(pid)) {
        return 0;
    }

    // 2. Arguments: PT_REGS_PARM2(ctx) is 'buf', PT_REGS_PARM3(ctx) is 'num'
    void *buf_ptr = (void *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);

    if (len <= 0) return 0;
    if (len > MAX_DATA_SIZE) len = MAX_DATA_SIZE;

    // 3. Reserve event
    struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->tgid = (__u32)pid_tgid;
    e->uid = bpf_get_current_uid_gid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->len = len;
    e->direction = 0; // Write
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 4. Capture plaintext (from user space buffer)
    bpf_probe_read_user(&e->data, len & (MAX_DATA_SIZE - 1), buf_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SSL_read(ssl, buf, num) - ENTRY
SEC("uprobe/SSL_read")
int probe_SSL_read_enter(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 1. Filter
    if (!is_ai_process(pid)) {
        return 0;
    }

    // 2. Store context: where is the buffer?
    struct ssl_read_ctx read_ctx = {};
    read_ctx.buffer_addr = PT_REGS_PARM2(ctx);

    bpf_map_update_elem(&active_ssl_reads, &pid_tgid, &read_ctx, BPF_ANY);
    return 0;
}

// SSL_read(ssl, buf, num) - EXIT
SEC("uretprobe/SSL_read")
int probe_SSL_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 1. Retrieve context
    struct ssl_read_ctx *read_ctx = bpf_map_lookup_elem(&active_ssl_reads, &pid_tgid);
    if (!read_ctx) return 0;

    // 2. Check return value (bytes read)
    int len = PT_REGS_RC(ctx);
    if (len <= 0) {
        bpf_map_delete_elem(&active_ssl_reads, &pid_tgid);
        return 0; // Error or EOF
    }

    if (len > MAX_DATA_SIZE) len = MAX_DATA_SIZE;

    // 3. Reserve event
    struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_ssl_reads, &pid_tgid);
        return 0;
    }

    e->pid = pid;
    e->tgid = (__u32)pid_tgid;
    e->uid = bpf_get_current_uid_gid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->len = len;
    e->direction = 1; // Read
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 4. Capture plaintext (buffer is now filled)
    bpf_probe_read_user(&e->data, len & (MAX_DATA_SIZE - 1), (void *)read_ctx->buffer_addr);

    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&active_ssl_reads, &pid_tgid);
    return 0;
}

// Clean up ai_pids on process exit to prevent map exhaustion.
// Handles both Go-registered and kernel-inherited (lazy) entries.
SEC("tp/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&ai_pids, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
