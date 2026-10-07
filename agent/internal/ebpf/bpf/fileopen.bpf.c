// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// fileopen.bpf.c - eBPF program to trace file open operations
//
// This program attaches to the openat syscall and captures file access events.
// It filters for sensitive credential paths to reduce noise.
//
// Credential paths monitored:
// - ~/.ssh/* (SSH keys)
// - ~/.aws/* (AWS credentials)
// - ~/.config/gcloud/* (GCP credentials)
// - ~/.azure/* (Azure credentials)
// - ~/.kube/* (Kubernetes config)
// - ~/.gnupg/* (GPG keys)
// - Browser credential stores

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ARGSIZE 256
#define TASK_COMM_LEN 16

// Event structure for file open operations
struct file_event {
    __u32 pid;           // Process ID
    __u32 ppid;          // Parent process ID
    __u32 uid;           // User ID
    __u32 gid;           // Group ID
    __u64 timestamp_ns;  // Nanoseconds since boot
    __s32 flags;         // Open flags (O_RDONLY, O_WRONLY, etc.)
    char comm[TASK_COMM_LEN];   // Command name
    char filename[ARGSIZE];      // File path being opened
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);  // 8MB buffer (Safe: ~48MB total for 6 collectors)
} file_events SEC(".maps");

// Per-CPU scratch buffer to avoid stack limit and double-reads
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[256]);
} scratch_map SEC(".maps");

// Check if path contains sensitive credential patterns
// Returns 1 if path should be captured, 0 otherwise
static __always_inline int is_sensitive_path(const char *buf) {
    // Check for common credential path patterns
    // We check for substrings that indicate sensitive files
    
    // Check for home directory credential paths
    // Pattern: contains ".ssh", ".aws", ".kube", ".gnupg", ".azure", ".config/gcloud"
    
    // SSH keys
    if (buf[0] == '/' || buf[0] == '.') {
        for (int i = 0; i < 50; i++) {
            if (buf[i] == 0) break;
            
            // Check for ".ssh"
            if (buf[i] == '.' && buf[i+1] == 's' && buf[i+2] == 's' && buf[i+3] == 'h') {
                return 1;
            }
            // Check for ".aws"
            if (buf[i] == '.' && buf[i+1] == 'a' && buf[i+2] == 'w' && buf[i+3] == 's') {
                return 1;
            }
            // Check for ".kube"
            if (buf[i] == '.' && buf[i+1] == 'k' && buf[i+2] == 'u' && buf[i+3] == 'b' && buf[i+4] == 'e') {
                return 1;
            }
            // Check for ".gnupg"
            if (buf[i] == '.' && buf[i+1] == 'g' && buf[i+2] == 'n' && buf[i+3] == 'u') {
                return 1;
            }
            // Check for ".azure"
            if (buf[i] == '.' && buf[i+1] == 'a' && buf[i+2] == 'z' && buf[i+3] == 'u') {
                return 1;
            }
            // Check for "gcloud"
            if (buf[i] == 'g' && buf[i+1] == 'c' && buf[i+2] == 'l' && buf[i+3] == 'o') {
                return 1;
            }
        }
        
        // Check for browser credential stores
        // Chrome: "Login Data", "Cookies"
        // Firefox: "logins.json", "cookies.sqlite"
        for (int i = 0; i < 50; i++) {
            if (buf[i] == 0) break;
            
            // "Login Data" (Chrome)
            if (buf[i] == 'L' && buf[i+1] == 'o' && buf[i+2] == 'g' && buf[i+3] == 'i' && buf[i+4] == 'n' &&
                buf[i+5] == ' ' && buf[i+6] == 'D' && buf[i+7] == 'a' && buf[i+8] == 't' && buf[i+9] == 'a') {
                return 1;
            }
            // "logins.json" (Firefox)
            if (buf[i] == 'l' && buf[i+1] == 'o' && buf[i+2] == 'g' && buf[i+3] == 'i' && buf[i+4] == 'n' &&
                buf[i+5] == 's' && buf[i+6] == '.' && buf[i+7] == 'j' && buf[i+8] == 's' && buf[i+9] == 'o' && buf[i+10] == 'n') {
                return 1;
            }
            // "Cookies" (strict match)
            if (buf[i] == 'C' && buf[i+1] == 'o' && buf[i+2] == 'o' && buf[i+3] == 'k' && buf[i+4] == 'i' && buf[i+5] == 'e' && buf[i+6] == 's') {
                return 1;
            }
            // "cookies.sqlite" (Firefox)
            if (buf[i] == 'c' && buf[i+1] == 'o' && buf[i+2] == 'o' && buf[i+3] == 'k' && buf[i+4] == 'i' && buf[i+5] == 'e' && 
                buf[i+6] == 's' && buf[i+7] == '.') {
                return 1;
            }
        }
    }
    
    // Also capture ANY file access in /home/ directory (user activity)
    if (buf[0] == '/' && buf[1] == 'h' && buf[2] == 'o' && buf[3] == 'm' && buf[4] == 'e' && buf[5] == '/') {
        return 1;
    }

    return 0;
}

// Tracepoint for sys_enter_openat
// This fires when any process calls openat() syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    // Get filename from syscall args
    // openat(int dfd, const char *filename, int flags, umode_t mode)
    const char *filename_ptr = (const char *)ctx->args[1];
    
    // Use per-cpu scratch map to read filename (avoids stack limit and double reading)
    __u32 key = 0;
    char *filename_buf = bpf_map_lookup_elem(&scratch_map, &key);
    if (!filename_buf) {
        return 0;
    }
    
    // Read filename into scratch buffer
    long ret = bpf_probe_read_user_str(filename_buf, 256, filename_ptr);
    if (ret <= 0) {
        return 0;
    }
    
    // Check if sensitive
    if (!is_sensitive_path(filename_buf)) {
        return 0;
    }
    
    struct file_event *e;
    struct task_struct *task;
    
    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
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
    e->flags = (int)ctx->args[2];  // Open flags
    
    // Get command name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Get parent PID
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    // Copy filename from scratch buffer to ring buffer event manually
    // This avoids reliance on memcpy or helpers that might fail across map/ringbuf boundaries
    // We limit copy to 256 bytes (ARGSIZE) to capture full paths
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        e->filename[i] = filename_buf[i];
    }
    // Ensure null termination (buffer is 256 bytes)
    e->filename[255] = 0;
    
    // Submit event
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
