package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/model"
)

func TestHTTPTransport_SendHeartbeat_ParsesBackendJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/heartbeat" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid state transition","code":"bad_request"}`))
	}))
	defer srv.Close()

	tr := NewHTTPTransport("raw-api-key", srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := tr.SendHeartbeat(ctx, model.Heartbeat{
		AgentID:   "a1",
		Hostname:  "h",
		OS:        "linux",
		Version:   "1",
		Profile:   "developer",
		State:     model.StateRunning,
		Timestamp: time.Now().UTC(),
	})

	if err == nil {
		t.Fatalf("expected error")
	}
	be, ok := err.(*BackendError)
	if !ok {
		t.Fatalf("expected *BackendError, got %T: %v", err, err)
	}
	if be.Status != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", be.Status, http.StatusBadRequest)
	}
	if be.Code != "bad_request" {
		t.Fatalf("code=%q want bad_request", be.Code)
	}
	if be.Msg != "invalid state transition" {
		t.Fatalf("msg=%q want %q", be.Msg, "invalid state transition")
	}
}

func TestHTTPTransport_SendTelemetryBatch_UsesTelemetryURL(t *testing.T) {
	telemetryCalled := false
	telemetrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/telemetry" {
			http.NotFound(w, r)
			return
		}
		telemetryCalled = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer telemetrySrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not hit backend", http.StatusInternalServerError)
	}))
	defer backendSrv.Close()

	tr := NewHTTPTransportWithTelemetryURL("raw-api-key", backendSrv.URL, telemetrySrv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := tr.SendTelemetryBatch(ctx, model.TelemetryBatch{
		Events: []model.TelemetryEvent{
			{
				AgentID:   "a1",
				EventType: "agent_log",
				Timestamp: time.Now().UTC(),
				Payload:   []byte(`{"msg":"hi"}`),
			},
		},
	})
	if err != nil {
		t.Fatalf("SendTelemetryBatch error: %v", err)
	}
	if !telemetryCalled {
		t.Fatalf("expected telemetry URL to be called")
	}
}
