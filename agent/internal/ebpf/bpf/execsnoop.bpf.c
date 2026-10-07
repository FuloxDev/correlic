// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// execsnoop.bpf.c - eBPF program to trace process executions
//
// This program attaches to the sched_process_exec tracepoint and captures
// information about every new process execution on the system.
//
// 🎓 eBPF LESSON 1: What is this file?
// ------------------------------------
// This is a "BPF program" written in restricted C. It will be compiled to
// eBPF bytecode and loaded into the Linux kernel. The kernel runs this code
// in a sandbox (the eBPF VM) every time a process exec happens.
//
// Key constraints:
// - No loops with unbounded iterations (kernel verifier rejects them)
// - No calling arbitrary functions (only BPF helper functions)
// - Stack limited to 512 bytes
// - Must be statically verifiable as safe

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum sizes for strings
#define ARGSIZE 256
#define TASK_COMM_LEN 16
#define MAX_ARGS 20
#define TOTAL_MAX_ARGS_LEN 1024
#define MAX_ARG_LEN 256

// 🎓 eBPF LESSON 2: Event structure
// ---------------------------------
// This struct defines the data we'll send from kernel to userspace.
// Both the BPF program and Go code must agree on this layout!
struct event {
    __u32 pid;           // Process ID
    __u32 ppid;          // Parent process ID
    __u32 gppid;         // Grandparent process ID (for correlation)
    __u32 uid;           // User ID
    __u32 gid;           // Group ID
    __u64 timestamp_ns;  // Nanoseconds since boot
    char comm[TASK_COMM_LEN];   // Command name (e.g., "curl")
    char pcomm[TASK_COMM_LEN];  // Parent command name (e.g., "bash")
    char filename[ARGSIZE];     // Full path to executable
    int retval;                 // Return value (0 for exec entry)
    int args_size;              // Number of bytes written to args array
    char args[TOTAL_MAX_ARGS_LEN]; // Concatenated arguments string
};

// Map to temporarily store exec arguments across tracepoints
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // pid
    __type(value, struct event);
} execs_in_flight SEC(".maps");

// Map used as a per-cpu temporary heap to construct the empty event
// This bypasses the 512-byte eBPF stack limit limit
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} heap_event SEC(".maps");

// 🎓 eBPF LESSON 3: BPF Maps
// --------------------------
// Maps are shared data structures between BPF programs and userspace.
// This "ring buffer" is a high-performance way to send events to Go.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);  // 8MB buffer
} events SEC(".maps");

static __always_inline int __tracepoint__syscalls__sys_enter_exec(struct trace_event_raw_sys_enter *ctx, const char **argv)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct event *e;
    
    // Allocate space for event in the hash map (not ring buffer yet!)
    // We cannot submit to ring buffer until sched_process_exec confirms success
    // We use a per-cpu array as a heap buffer to bypass the 512b stack limit
    __u32 zero = 0;
    struct event *empty_event = bpf_map_lookup_elem(&heap_event, &zero);
    if (!empty_event) return 0;
    
    // Clear out the struct explicitly instead of relying on {} on stack
    empty_event->args_size = 0;
    empty_event->args[0] = '\0';
    
    if (bpf_map_update_elem(&execs_in_flight, &pid, empty_event, BPF_ANY) != 0) {
        // Map might be full
        return 0; // stop processing if we can't allocate
    }
    
    e = bpf_map_lookup_elem(&execs_in_flight, &pid);
    if (!e) return 0;
    
    const char *argp;    e->args_size = 0;
    e->args[0] = '\0';

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0) break;
        if (!argp) break;

        // BPF verifier loves constant offsets, so we read directly into a statically known bound chunk
        // Use exactly MAX_ARG_LEN per read to satisfy the verifier
        int sz = 0;
        int offset = e->args_size;
        
        // The mask below only preserves offsets up to 511, so stop collecting
        // once the buffer is past that point instead of wrapping onto argv[0].
        // (511 + MAX_ARG_LEN = 767 < TOTAL_MAX_ARGS_LEN, so the read stays in bounds.)
        if (offset > 511) {
            break;
        }
        
        // Inform verifier that offset is bounded: 511 + 256 = 767 <= 1024
        offset &= 511;
        
        sz = bpf_probe_read_user_str(&e->args[offset], MAX_ARG_LEN, argp);
        
        if (sz > 0) {
            e->args_size += sz;
        } else {
            // If the read fails for an argument (e.g. paged out or tool long), 
            // continue trying to read subsequent arguments instead of bailing out completely.
            continue;
        }
    }
    
    return 0;
}

// Tracepoint for sys_enter_execve to capture arguments
// This fires *before* sched_process_exec
SEC("tp/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    // execve(const char *filename, char *const argv[], char *const envp[])
    // args[0] = filename, args[1] = argv, args[2] = envp
    const char **argv = (const char **)(ctx->args[1]);
    return __tracepoint__syscalls__sys_enter_exec(ctx, argv);
}

// Tracepoint for sys_enter_execveat to capture arguments
// This fires *before* sched_process_exec
SEC("tp/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
    // execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
    // args[0] = dirfd, args[1] = pathname, args[2] = argv
    const char **argv = (const char **)(ctx->args[2]);
    return __tracepoint__syscalls__sys_enter_exec(ctx, argv);
}

static __always_inline int __tracepoint__syscalls__sys_exit_exec(struct trace_event_raw_sys_exit *ctx)
{
    // If the execution failed (e.g., -ENOENT during $PATH search),
    // clean up our temporary arguments map immediately to prevent leak/race.
    // Explicitly cast to long to ensure negative values are properly evaluated.
    if ((long)ctx->ret < 0) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;
        bpf_map_delete_elem(&execs_in_flight, &pid);
    }
    return 0;
}

// Tracepoint for sys_exit_execve to clean up on failure
SEC("tp/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    return __tracepoint__syscalls__sys_exit_exec(ctx);
}

// Tracepoint for sys_exit_execveat to clean up on failure
SEC("tp/syscalls/sys_exit_execveat")
int tracepoint__syscalls__sys_exit_execveat(struct trace_event_raw_sys_exit *ctx)
{
    return __tracepoint__syscalls__sys_exit_exec(ctx);
}

// 🎓 eBPF LESSON 4: Tracepoints
// -----------------------------
// SEC("tp/...") tells the loader where to attach this function.
// "sched/sched_process_exec" fires every time execve() completes successfully.
//
// The 'ctx' parameter contains tracepoint-specific data, but we mostly
// read from current task (bpf_get_current_task()) for rich info.
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e;
    struct task_struct *task;
    
    // 🎓 Reserve space in the ring buffer for our event
    // If buffer is full, bpf_ringbuf_reserve returns NULL
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;  // Drop event if buffer full (graceful degradation)
    }
    
    // 🎓 Get current process info
    // bpf_get_current_pid_tgid() returns (tgid << 32 | pid)
    // For single-threaded: pid == tgid (thread group ID)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    e->pid = pid;  // Upper 32 bits = tgid (what users call "PID")
    
    // Try to recover arguments from the sys_enter_execve hook
    struct event *inflight = bpf_map_lookup_elem(&execs_in_flight, &pid);
    if (inflight) {
        // Copy arguments over to the ring buffer struct
        e->args_size = inflight->args_size;
        
        // We can't __builtin_memcpy variable sizes easily due to verifier,
        // but we can bounded memcpy up to max sizes or unrolled loops.
        // Easiest is to just copy the whole fixed buffer for simplicity.
        // It's 512 bytes, handled easily by kernel.
        __builtin_memcpy(e->args, inflight->args, TOTAL_MAX_ARGS_LEN);
        
        // Clean up hash map
        bpf_map_delete_elem(&execs_in_flight, &pid);
    } else {
        e->args_size = 0;
        e->args[0] = '\0';
    }
    
    // Get UID/GID
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;
    
    // Timestamp
    e->timestamp_ns = bpf_ktime_get_ns();
    
    // 🎓 Read process name (comm)
    // bpf_get_current_comm() is a helper that safely copies comm
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 🎓 Read parent PID using task_struct
    // bpf_get_current_task() returns pointer to current task_struct
    task = (struct task_struct *)bpf_get_current_task();
    
    // BPF_CORE_READ handles kernel structure layout differences (CO-RE)
    // This works across different kernel versions without recompilation!
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    
    // Read parent command name using bpf_probe_read_kernel_str (safe for kernel strings)
    // BPF_CORE_READ_STR_INTO can return garbage - use the proper helper instead
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);
    
    // Read grandparent PID for deeper correlation chains
    struct task_struct *gparent = BPF_CORE_READ(parent, real_parent);
    e->gppid = BPF_CORE_READ(gparent, tgid);
    
    // Read executable filename from tracepoint __data field
    // __data_loc_filename encodes: upper 16 bits = length, lower 16 bits = offset
    unsigned int data_loc = ctx->__data_loc_filename;
    unsigned int fname_off = data_loc & 0xFFFF;
    unsigned int fname_len = (data_loc >> 16) & 0xFFFF;
    
    // Cap length to prevent verifier errors (ARGSIZE = 256)
    if (fname_len > ARGSIZE - 1) {
        fname_len = ARGSIZE - 1;
    }
    
    // Read filename with bounded length
    if (fname_len > 0) {
        bpf_probe_read_kernel(&e->filename, fname_len & (ARGSIZE - 1), (void *)ctx + fname_off);
        e->filename[ARGSIZE - 1] = '\0';  // Ensure null termination
    } else {
        // Fallback to comm
        bpf_get_current_comm(&e->filename, sizeof(e->filename));
    }
    
    e->retval = 0;  // exec entry, not exit
    
    // 🎓 Submit the event to userspace
    // bpf_ringbuf_submit() makes the event visible to the reader
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

// 🎓 eBPF LESSON 5: License
// -------------------------
// BPF programs MUST have a license. GPL allows using all BPF helpers.
// Some helpers (like bpf_probe_read_kernel) require GPL license.
char LICENSE[] SEC("license") = "GPL";
