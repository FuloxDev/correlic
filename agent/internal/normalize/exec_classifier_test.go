package normalize

import (
	"testing"
)

func TestClassifyExec_EmptyOrNonPrintable(t *testing.T) {
	got := ClassifyExec("", nil, 0)
	if got.Class != ClassUnknown || got.Normalized {
		t.Errorf("empty exePath: got %+v", got)
	}
	got = ClassifyExec("\u000e", nil, 0)
	if got.Class != ClassUnknown || got.Normalized {
		t.Errorf("non-printable: got %+v", got)
	}
}

func TestClassifyExec_BashC_ShellEphemeral(t *testing.T) {
	got := ClassifyExec("/usr/bin/bash", []string{"bash", "-c", "echo hi"}, 1)
	if got.Class != ClassShell || got.Role != RoleEphemeral || got.Group != "shell" || !got.Normalized {
		t.Errorf("bash -c: got %+v", got)
	}
}

func TestClassifyExec_Python_RuntimeInterpreter(t *testing.T) {
	got := ClassifyExec("/usr/bin/python3", []string{"python3", "script.py"}, 1)
	if got.Class != ClassRuntime || got.Role != RoleInterpreter || got.Group != "python" || !got.Normalized {
		t.Errorf("python script: got %+v", got)
	}
}

func TestClassifyExec_Gen_Helper(t *testing.T) {
	got := ClassifyExec("/tmp/gen", nil, 1)
	if got.Class != ClassHelper || got.Role != RoleFork || got.Group != "gen" || !got.Normalized {
		t.Errorf("gen: got %+v", got)
	}
}

func TestClassifyExec_PrimaryEntrypoint(t *testing.T) {
	got := ClassifyExec("/usr/bin/curl", []string{"curl", "https://example.com"}, 1)
	if got.Class != ClassPrimary || got.Role != RoleEntrypoint || !got.Normalized {
		t.Errorf("curl: got %+v", got)
	}
}

func TestClassifyExec_Sh_Shell(t *testing.T) {
	got := ClassifyExec("/bin/sh", []string{"sh"}, 0)
	if got.Class != ClassShell || got.Role != RoleEphemeral || !got.Normalized {
		t.Errorf("/bin/sh: got %+v", got)
	}
}
