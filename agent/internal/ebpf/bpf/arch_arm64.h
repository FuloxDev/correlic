// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// arch_arm64.h - register-file shim for the arm64 build of the kprobe programs.
//
// Include it after "vmlinux.h" and before <bpf/bpf_tracing.h> in every
// program that uses PT_REGS_PARMn() or BPF_KPROBE() (dns.bpf.c, bind.bpf.c).
// It is empty for every target except arm64.
//
// Why it is needed: bpf/vmlinux.h is generated from an x86_64 kernel, so it
// defines the x86 `struct pt_regs` and no `struct user_pt_regs`. When bpf2go
// compiles with `-target arm64` it defines __TARGET_ARCH_arm64, and libbpf's
// bpf_tracing.h then expands PT_REGS_PARMn(ctx) to
//
//     ((const struct user_pt_regs *)(ctx))->regs[n - 1]
//
// (PT_REGS_SP/IP use `sp`/`pc`), which does not compile without that type.
//
// Why the declaration below is correct: on arm64 a kprobe program receives
// the kernel's `struct pt_regs` (arch/arm64/include/asm/ptrace.h), whose
// first member is the user-visible register file:
//
//     struct pt_regs {
//         union {
//             struct user_pt_regs user_regs;
//             struct { u64 regs[31]; u64 sp; u64 pc; u64 pstate; };
//         };
//         u64 orig_x0;
//         ...
//     };
//
// `struct user_pt_regs` (arch/arm64/include/uapi/asm/ptrace.h) is part of the
// kernel's user ABI (ptrace, signal frames, perf sample regs) and therefore
// has a fixed layout: x0..x30 at byte offsets 0..240, sp at 248, pc at 256,
// pstate at 264. Under the AAPCS64 calling convention x0 and x1 (regs[0],
// regs[1]) carry the first two integer arguments, which is what
// PT_REGS_PARM1/PARM2 read. The struct is declared outside vmlinux.h's
// `preserve_access_index` pragma on purpose: the offsets are ABI constants,
// so the plain PT_REGS_PARMn macros read them directly and no CO-RE
// relocation against the running kernel is involved. The CO-RE flavours
// (PT_REGS_PARMn_CORE, PT_REGS_PARMn_SYSCALL) would need the real arm64
// `struct pt_regs` from an arm64 vmlinux.h; no program in this directory
// uses them (grep for `_CORE(` and `_SYSCALL(`).
//
// Every other field access in the programs (task_struct, sock, msghdr,
// iov_iter, linux_binprm, tracepoint contexts) goes through BPF_CORE_READ or
// preserve_access_index and is relocated by name against the running
// kernel's BTF, so it is architecture independent and unchanged.
#ifndef __CORRELIC_ARCH_ARM64_H__
#define __CORRELIC_ARCH_ARM64_H__

#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

#endif /* __CORRELIC_ARCH_ARM64_H__ */
