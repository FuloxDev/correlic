//go:build linux

package ebpf

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestLoadBPFObjects loads every generated BPF object into the kernel, which
// runs CO-RE relocation against the running kernel's BTF and the verifier
// over each program. Nothing is attached. The test skips where that is not
// possible (no BTF, no CAP_BPF).
func TestLoadBPFObjects(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("kernel BTF not available")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}

	loaders := map[string]func() (interface{ Close() error }, error){
		"execsnoop": func() (interface{ Close() error }, error) {
			o := &execsnoopObjects{}
			return o, loadExecsnoopObjects(o, nil)
		},
		"exit": func() (interface{ Close() error }, error) {
			o := &exitObjects{}
			return o, loadExitObjects(o, nil)
		},
		"fork": func() (interface{ Close() error }, error) {
			o := &forkObjects{}
			return o, loadForkObjects(o, nil)
		},
		"connect": func() (interface{ Close() error }, error) {
			o := &connectObjects{}
			return o, loadConnectObjects(o, nil)
		},
		"fileopen": func() (interface{ Close() error }, error) {
			o := &fileopenObjects{}
			return o, loadFileopenObjects(o, nil)
		},
		"dns": func() (interface{ Close() error }, error) {
			o := &dnsObjects{}
			return o, loadDnsObjects(o, nil)
		},
		"bind": func() (interface{ Close() error }, error) {
			o := &bindObjects{}
			return o, loadBindObjects(o, nil)
		},
		"unlink": func() (interface{ Close() error }, error) {
			o := &unlinkObjects{}
			return o, loadUnlinkObjects(o, nil)
		},
		"setuid": func() (interface{ Close() error }, error) {
			o := &setuidObjects{}
			return o, loadSetuidObjects(o, nil)
		},
	}

	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			objs, err := load()
			if err != nil {
				if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted") {
					t.Skipf("insufficient privileges to load BPF: %v", err)
				}
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("verifier rejected %s:\n%+v", name, ve)
				}
				t.Fatalf("load %s: %v", name, err)
			}
			_ = objs.Close()
		})
	}
}
