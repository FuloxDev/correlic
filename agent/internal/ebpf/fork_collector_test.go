//go:build linux

package ebpf

import (
	"encoding/binary"
	"log/slog"
	"testing"
)

func forkRecord(ppid, ptgid, cpid, ctgid uint32, exit bool, pcomm, ccomm string) []byte {
	data := make([]byte, 72)
	binary.LittleEndian.PutUint32(data[0:4], ppid)
	binary.LittleEndian.PutUint32(data[4:8], ptgid)
	binary.LittleEndian.PutUint32(data[8:12], cpid)
	binary.LittleEndian.PutUint32(data[12:16], ctgid)
	binary.LittleEndian.PutUint32(data[16:20], 1000)
	binary.LittleEndian.PutUint64(data[24:32], 42)
	if exit {
		binary.LittleEndian.PutUint64(data[32:40], 0xFFFFFFFFFFFFFFFF)
	}
	copy(data[40:56], pcomm)
	copy(data[56:72], ccomm)
	return data
}

func TestParseForkEvent_ThreadVsProcess(t *testing.T) {
	ev, err := parseForkEvent(forkRecord(10, 10, 11, 11, false, "bash", "bash"))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.IsFork() || ev.IsThread() || ev.IsExit() {
		t.Errorf("new process: IsFork=%v IsThread=%v IsExit=%v", ev.IsFork(), ev.IsThread(), ev.IsExit())
	}

	thr, _ := parseForkEvent(forkRecord(20, 20, 25, 20, false, "node", "node"))
	if !thr.IsThread() || thr.IsFork() {
		t.Errorf("thread: IsThread=%v IsFork=%v", thr.IsThread(), thr.IsFork())
	}

	ex, _ := parseForkEvent(forkRecord(0, 0, 25, 20, true, "", "node"))
	if !ex.IsExit() || !ex.IsThread() {
		t.Errorf("thread exit: IsExit=%v IsThread=%v", ex.IsExit(), ex.IsThread())
	}
}

func TestForkCollector_TreeKeyedByTGIDAndBounded(t *testing.T) {
	c := &ForkCollector{tree: make(map[uint32]*ProcessNode), logger: slog.Default()}

	// Parent 100 forks 101 from one of its threads (task 105).
	c.updateTree(ForkEvent{ParentPID: 105, ParentTGID: 100, ChildPID: 101, ChildTGID: 101, ChildComm: "sh"})
	c.updateTree(ForkEvent{ParentPID: 1, ParentTGID: 1, ChildPID: 100, ChildTGID: 100, ChildComm: "node"})
	c.updateTree(ForkEvent{ParentPID: 100, ParentTGID: 100, ChildPID: 102, ChildTGID: 102, ChildComm: "git"})

	tree := c.GetTree()
	if tree[101] == nil || tree[101].PPID != 100 {
		t.Fatalf("child must be keyed by tgid with ppid = parent tgid, got %+v", tree[101])
	}
	if got := tree[100].Children; len(got) != 1 || got[0] != 102 {
		t.Errorf("children of 100 = %v, want [102]", got)
	}

	// A thread exit must not remove the process.
	c.updateTree(ForkEvent{ChildPID: 107, ChildTGID: 102, CloneFlags: 0xFFFFFFFFFFFFFFFF})
	// (the collector filters threads before updateTree, but exits are keyed by tgid anyway)
	// Leader exit removes it and unlinks it from the parent.
	c.updateTree(ForkEvent{ChildPID: 102, ChildTGID: 102, CloneFlags: 0xFFFFFFFFFFFFFFFF})
	tree = c.GetTree()
	if tree[102] != nil {
		t.Error("exited process should be removed from the tree")
	}
	if len(tree[100].Children) != 0 {
		t.Errorf("exited child should be unlinked from parent, got %v", tree[100].Children)
	}

	// Bounded: insert more than maxTreeEntries and verify the oldest go first.
	for i := uint32(1000); i < 1000+maxTreeEntries+5; i++ {
		c.updateTree(ForkEvent{ParentPID: 1, ParentTGID: 1, ChildPID: i, ChildTGID: i, ChildComm: "x"})
	}
	c.mu.RLock()
	n := len(c.tree)
	_, oldestPresent := c.tree[100]
	c.mu.RUnlock()
	if n > maxTreeEntries {
		t.Errorf("tree size %d exceeds cap %d", n, maxTreeEntries)
	}
	if oldestPresent {
		t.Error("oldest entry should have been evicted")
	}
}
