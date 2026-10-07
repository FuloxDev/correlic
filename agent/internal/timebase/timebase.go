//go:build linux

package timebase

import (
	"time"

	"golang.org/x/sys/unix"
)

// Monotonic ns ranges: typical uptime 1 year ≈ 3e16 ns. Unix epoch ns for 2020–2030 ≈ 1.6e18–2e18.
const (
	unixEpochNsMin = 1e18   // 2001-09-09
	unixEpochNsMax = 2.5e18 // 2049
)

// Timebase stores wall-clock and monotonic clock at a reference moment (e.g. agent startup).
// Use ToWall(monotonicNs) to convert eBPF ktime (bpf_ktime_get_ns()) to correct wall-clock time.
type Timebase struct {
	Wall time.Time
	Mono uint64
}

// Init captures the current wall time and monotonic clock. Call once at agent startup.
func Init() (*Timebase, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, err
	}
	monoNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	return &Timebase{
		Wall: time.Now(),
		Mono: monoNs,
	}, nil
}

// ToWall converts a timestamp from eBPF to wall-clock time.
// If the value is in Unix epoch ns range (some kernels/configs return real time instead of monotonic),
// we use it as epoch ns. Otherwise we treat it as monotonic and convert via the timebase.
func (tb *Timebase) ToWall(tsNs uint64) time.Time {
	if tsNs >= unixEpochNsMin && tsNs <= unixEpochNsMax {
		return time.Unix(0, int64(tsNs))
	}
	delta := int64(tsNs - tb.Mono)
	return tb.Wall.Add(time.Duration(delta))
}
