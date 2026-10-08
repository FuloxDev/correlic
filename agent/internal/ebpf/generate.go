//go:build linux

// Package ebpf provides eBPF-based process execution monitoring.
//
// 🎓 eBPF LESSON 6: Code Generation
// ----------------------------------
// This file uses go:generate to invoke bpf2go, which:
// 1. Compiles the .bpf.c file to eBPF bytecode using clang
// 2. Generates Go code that embeds the bytecode
// 3. Creates type-safe Go structs matching the C structs
//
// Run: go generate ./internal/ebpf/...

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 execsnoop bpf/execsnoop.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 fileopen bpf/fileopen.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 connect bpf/connect.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 dns bpf/dns.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 bind bpf/bind.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 unlink bpf/unlink.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 setuid bpf/setuid.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 fork bpf/fork.bpf.c -- -I/usr/include -I.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 exit bpf/exit.bpf.c -- -I/usr/include -I.
