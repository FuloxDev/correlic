//go:build darwin && esf

package esf

import (
	"sync"
	"unsafe"
)

// clientRegistry maps opaque pointers (used as keys in C callbacks) to *Client.
// This avoids storing Go pointers in C memory (cgo rule violation).
type registry struct {
	mu      sync.Mutex
	counter uintptr
	entries map[uintptr]*Client
}

func newClientRegistry() *registry {
	return &registry{entries: make(map[uintptr]*Client)}
}

func (r *registry) register(c *Client) unsafe.Pointer {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counter++
	key := r.counter
	r.entries[key] = c
	// Return the key as an unsafe.Pointer — never dereferenced in C, only echoed back.
	return unsafe.Pointer(key) //nolint:unsafeptr
}

func (r *registry) unregister(ptr unsafe.Pointer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, uintptr(ptr))
}

func (r *registry) lookup(ptr unsafe.Pointer) *Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[uintptr(ptr)]
}
