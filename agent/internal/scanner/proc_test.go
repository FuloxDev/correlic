//go:build linux

package scanner

import "testing"

func TestHasAIAncestor(t *testing.T) {
	// 1 -> 10 (claude) -> 20 (bash) -> 30 (bash, also matches) -> 40 (cat)
	//   -> 50 (cursor)
	procs := map[int]procInfo{
		10: {pid: 10, ppid: 1, isAI: true},
		20: {pid: 20, ppid: 10},
		30: {pid: 30, ppid: 20, isAI: true},
		40: {pid: 40, ppid: 30},
		50: {pid: 50, ppid: 1, isAI: true},
		60: {pid: 60, ppid: 999}, // parent not in the snapshot
	}
	roots := map[int]bool{10: true, 30: true, 50: true}

	cases := map[int]bool{10: false, 30: true, 40: true, 50: false, 20: true, 60: false, 7: false}
	for pid, want := range cases {
		if got := hasAIAncestor(pid, procs, roots); got != want {
			t.Errorf("hasAIAncestor(%d) = %v, want %v", pid, got, want)
		}
	}

	// A ppid cycle must not loop forever.
	cyc := map[int]procInfo{2: {pid: 2, ppid: 3}, 3: {pid: 3, ppid: 2}}
	if hasAIAncestor(2, cyc, map[int]bool{}) {
		t.Error("cycle reported an ancestor")
	}
}
