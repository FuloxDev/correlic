package notification

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rfc5424Header matches "<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID "
// and captures PRI, timestamp, hostname, app, procid and msgid.
var rfc5424Header = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) `)

func TestBuildSyslogFrame(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 30, 45, 123000000, time.UTC)
	frame := string(buildSyslogFrame(syslogFacilities["local4"], "backend01", now, samplePayload("incident.created")))

	m := rfc5424Header.FindStringSubmatch(frame)
	if m == nil {
		t.Fatalf("frame does not start with an RFC 5424 header: %q", frame)
	}
	// local4 (20) * 8 + critical (2) = 162
	if m[1] != "162" {
		t.Errorf("PRI = %s, want 162", m[1])
	}
	if m[2] != "2026-10-09T12:30:45.123Z" {
		t.Errorf("timestamp = %s", m[2])
	}
	if m[3] != "backend01" || m[4] != "correlic" || m[5] != "-" || m[6] != "incident.created" {
		t.Errorf("header fields = %v", m[1:])
	}
	rest := frame[len(m[0]):]
	if !strings.HasPrefix(rest, "[correlic@32473 ") {
		t.Fatalf("structured data missing: %q", rest)
	}
	end := strings.Index(rest, "] ")
	sd := rest[:end+1]
	for _, want := range []string{
		`incident_id="inc-123"`, `severity="critical"`, `host_id="host-a"`,
		`category="credential_access"`, `detection_ids="ai.credential_access"`,
		`finding_ids="f-1,f-2"`, `finding_count="2"`, `mitre="T1552,T1552.004"`,
		`event="incident.created"`,
	} {
		if !strings.Contains(sd, want) {
			t.Errorf("structured data lacks %s: %s", want, sd)
		}
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(rest[end+2:]), &msg); err != nil {
		t.Fatalf("MSG is not JSON: %v (%q)", err, rest[end+2:])
	}
	if msg["event"] != "incident.created" {
		t.Errorf("MSG payload = %v", msg)
	}
}

func TestSyslogSeverityAndEscaping(t *testing.T) {
	p := samplePayload("test")
	inc := p["incident"].(map[string]any)
	inc["severity"] = "low"
	inc["host_id"] = `we"ird\host]`
	frame := string(buildSyslogFrame(syslogFacilities["local0"], "", time.Now(), p))
	if !strings.HasPrefix(frame, "<133>1 ") { // 16*8 + 5 (notice)
		t.Errorf("PRI for low/local0 = %q", frame[:8])
	}
	if !strings.Contains(frame, ` - correlic - test [`) { // empty hostname → NILVALUE
		t.Errorf("hostname nilvalue missing: %q", frame[:80])
	}
	if !strings.Contains(frame, `host_id="we\"ird\\host\]"`) {
		t.Errorf("SD escaping wrong: %q", frame)
	}
	inc["severity"] = "unexpected"
	frame = string(buildSyslogFrame(syslogFacilities["local0"], "h", time.Now(), p))
	if !strings.HasPrefix(frame, "<134>1 ") { // informational
		t.Errorf("PRI for unknown severity = %q", frame[:8])
	}
}

func TestSyslogSendUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	s := NewSyslogSender()
	s.hostname = "backend01"
	ep := Endpoint{ChannelType: ChannelSyslog, Config: map[string]any{
		"host": "127.0.0.1", "port": port, "protocol": SyslogUDP, "facility": "auth",
	}}
	if err := s.Send(context.Background(), ep, samplePayload("incident.escalated")); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	frame := string(buf[:n])
	m := rfc5424Header.FindStringSubmatch(frame)
	if m == nil {
		t.Fatalf("datagram is not RFC 5424: %q", frame)
	}
	// auth (4) * 8 + critical (2) = 34
	if m[1] != "34" || m[3] != "backend01" || m[6] != "incident.escalated" {
		t.Errorf("header = %v", m[1:])
	}
	if !strings.Contains(frame, `[correlic@32473 event="incident.escalated" incident_id="inc-123" severity="critical"`) {
		t.Errorf("structured data: %q", frame)
	}
	if strings.HasPrefix(frame, strconv.Itoa(len(frame))) {
		t.Error("UDP frames must not use octet-counting")
	}
}

func TestSyslogSendTCPOctetCounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()

	s := NewSyslogSender()
	ep := Endpoint{ChannelType: ChannelSyslog, Config: map[string]any{
		"host": "127.0.0.1", "port": ln.Addr().(*net.TCPAddr).Port, "protocol": SyslogTCP,
	}}
	if err := s.Send(context.Background(), ep, samplePayload("incident.created")); err != nil {
		t.Fatalf("send: %v", err)
	}
	var stream string
	select {
	case stream = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no tcp data")
	}
	sp := strings.IndexByte(stream, ' ')
	if sp < 0 {
		t.Fatalf("no octet count: %q", stream)
	}
	n, err := strconv.Atoi(stream[:sp])
	if err != nil || n != len(stream)-sp-1 {
		t.Fatalf("octet count %q does not match frame length %d", stream[:sp], len(stream)-sp-1)
	}
	// default facility local0 (16) * 8 + critical (2) = 130
	if !strings.HasPrefix(stream[sp+1:], "<130>1 ") {
		t.Errorf("frame = %q", stream[sp+1:sp+9])
	}
}

func TestSyslogSendUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	s := NewSyslogSender()
	ep := Endpoint{ChannelType: ChannelSyslog, Config: map[string]any{"host": "127.0.0.1", "port": port, "protocol": SyslogTCP}}
	if err := s.Send(context.Background(), ep, samplePayload("test")); err == nil {
		t.Fatal("expected a connection error")
	}
}
