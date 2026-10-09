package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// discordTestSender points the sender at an httptest server while keeping
// the host allowlist meaningful: the test server is reached through the
// client, the URL check is exercised separately.
func discordTestSender(srv *httptest.Server) *DiscordSender {
	s := NewDiscordSender().WithDashboardURL("https://correlic.example/")
	s.client = srv.Client()
	return s
}

func samplePayload(event string) map[string]any {
	return map[string]any{
		"event": event,
		"incident": map[string]any{
			"id":               "inc-123",
			"severity":         "critical",
			"confidence":       0.9,
			"title":            "AI agent read SSH private key",
			"summary":          "claude process read /home/u/.ssh/id_rsa",
			"host_id":          "host-a",
			"category":         "credential_access",
			"detection_ids":    []any{"ai.credential_access"},
			"mitre_techniques": []any{"T1552", "T1552.004"},
			"finding_ids":      []any{"f-1", "f-2"},
			"finding_count":    2,
			"started_at":       "2026-10-09T10:00:00Z",
		},
	}
}

func TestBuildDiscordMessage(t *testing.T) {
	msg := buildDiscordMessage(samplePayload("incident.created"), "https://correlic.example")
	embeds, _ := msg["embeds"].([]map[string]any)
	if len(embeds) != 1 {
		t.Fatalf("expected one embed, got %d", len(embeds))
	}
	e := embeds[0]
	if e["title"] != "CRITICAL: AI agent read SSH private key" {
		t.Errorf("title = %q", e["title"])
	}
	if e["color"] != discordColors["critical"] {
		t.Errorf("color = %v", e["color"])
	}
	if e["url"] != "https://correlic.example/incidents/inc-123" {
		t.Errorf("url = %v", e["url"])
	}
	fields, _ := e["fields"].([]map[string]any)
	got := map[string]string{}
	for _, f := range fields {
		got[f["name"].(string)] = f["value"].(string)
	}
	if got["Host"] != "host-a" || got["Rule"] != "ai.credential_access" || got["Findings"] != "2" {
		t.Errorf("fields = %+v", got)
	}
	if !strings.Contains(got["MITRE ATT&CK"], "T1552.004") {
		t.Errorf("mitre field = %q", got["MITRE ATT&CK"])
	}
	am, _ := msg["allowed_mentions"].(map[string]any)
	if parse, _ := am["parse"].([]string); parse == nil || len(parse) != 0 {
		t.Errorf("mentions must be disabled: %+v", msg["allowed_mentions"])
	}

	esc := buildDiscordMessage(samplePayload("incident.escalated"), "")
	title := esc["embeds"].([]map[string]any)[0]["title"].(string)
	if !strings.HasPrefix(title, "ESCALATED to CRITICAL") {
		t.Errorf("escalated title = %q", title)
	}
	if _, ok := esc["embeds"].([]map[string]any)[0]["url"]; ok {
		t.Error("no dashboard url configured, embed must not carry a link")
	}
}

func TestDiscordSend(t *testing.T) {
	var gotBody map[string]any
	var gotPath, gotUA string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUA = r.Header.Get("User-Agent")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// The sender's URL guard rejects anything but discord.com; route the
	// request to the test server by rewriting the Host at transport level.
	s := discordTestSender(srv)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (conn netConn, err error) {
		return dialTestServer(ctx, network, srv)
	}
	tr.TLSClientConfig.InsecureSkipVerify = true
	s.client = &http.Client{Transport: tr}
	useFakeResolver(t)
	lookupIPAlias(t, "discord.com", "93.184.216.34")

	ep := Endpoint{ChannelType: ChannelDiscord, Config: map[string]any{"webhook_url": "https://discord.com/api/webhooks/42/token"}}
	if err := s.Send(context.Background(), ep, samplePayload("incident.created")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotPath != "/api/webhooks/42/token" {
		t.Errorf("path = %q", gotPath)
	}
	if gotUA != "Correlic-Webhook/1.0" {
		t.Errorf("user-agent = %q", gotUA)
	}
	if gotBody["username"] != "Correlic" {
		t.Errorf("username = %v", gotBody["username"])
	}
	embeds, _ := gotBody["embeds"].([]any)
	if len(embeds) != 1 {
		t.Fatalf("embeds = %v", gotBody["embeds"])
	}

	// A non-Discord URL is rejected before any request is made.
	ep.Config["webhook_url"] = "https://public.example/api/webhooks/42/token"
	if err := s.Send(context.Background(), ep, samplePayload("incident.created")); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected the host allowlist to reject, got %v", err)
	}

	// Non-2xx is a delivery failure carrying the status.
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv2.Close()
	tr2 := tr.Clone()
	tr2.DialContext = func(ctx context.Context, network, _ string) (netConn, error) {
		return dialTestServer(ctx, network, srv2)
	}
	s.client = &http.Client{Transport: tr2}
	ep.Config["webhook_url"] = "https://discord.com/api/webhooks/42/token"
	err := s.Send(context.Background(), ep, samplePayload("incident.created"))
	if err == nil || CategorizeSendError(err) != "http 429" {
		t.Fatalf("expected http 429, got %v (%q)", err, CategorizeSendError(err))
	}
}
