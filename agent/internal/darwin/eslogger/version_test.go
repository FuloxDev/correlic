package eslogger

import (
	"errors"
	"testing"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
		wantErr      bool
	}{
		{"13.0", 13, 0, false},
		{"14.3.1", 14, 3, false},
		{"15.1", 15, 1, false},
		{"26.0.1", 26, 0, false},
		{"12.7.6\n", 12, 7, false},
		{"13", 13, 0, false},
		{"", 0, 0, true},
		{"abc", 0, 0, true},
		{"13.x", 0, 0, true},
	}
	for _, c := range cases {
		major, minor, err := parseVersion(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseVersion(%q) expected error", c.in)
			}
			continue
		}
		if err != nil || major != c.major || minor != c.minor {
			t.Errorf("parseVersion(%q) = %d.%d, %v; want %d.%d", c.in, major, minor, err, c.major, c.minor)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	for _, v := range []string{"13.0", "13.6.7", "14.0", "15.2", "26.0"} {
		if err := checkVersion(v); err != nil {
			t.Errorf("checkVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range []string{"12.7.6", "11.0", "10.15.7"} {
		if err := checkVersion(v); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("checkVersion(%q) = %v, want ErrUnsupportedVersion", v, err)
		}
	}
	// Unknown versions are not an error: the binary's presence decides.
	if err := checkVersion("unknown"); err != nil {
		t.Errorf("checkVersion(unknown) = %v", err)
	}
}
