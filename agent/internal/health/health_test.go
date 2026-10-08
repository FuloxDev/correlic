package health

import (
	"errors"
	"testing"
	"time"
)

func TestAuthRejectedThrottledPerMinute(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	resetForTesting(func() time.Time { return now })
	defer resetForTesting(nil)

	if !ReportAuthRejected("ingest", 401, errors.New("unauthorized")) {
		t.Fatal("first rejection should log")
	}
	for i := 0; i < 10; i++ {
		if ReportAuthRejected("ingest", 401, nil) {
			t.Fatal("repeated rejection within a minute must not log")
		}
	}
	now = now.Add(WarnThrottle)
	if !ReportAuthRejected("ingest", 403, nil) {
		t.Fatal("rejection after a minute should log again")
	}
	st := Snapshot()["ingest"]
	if st.Status != 403 || st.Dropped != 12 {
		t.Errorf("state = %+v, want status 403 dropped 12", st)
	}

	// A different component has its own throttle window.
	if !ReportAuthRejected("telemetry", 401, nil) {
		t.Fatal("other component should log independently")
	}

	ReportOK("ingest")
	if _, still := Snapshot()["ingest"]; still {
		t.Error("ReportOK must clear the failing state")
	}
	if !Failing() {
		t.Error("telemetry should still be failing")
	}
}
