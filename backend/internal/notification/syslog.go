package notification

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// SyslogSender delivers notifications as RFC 5424 syslog messages over UDP,
// TCP (RFC 6587 octet-counting framing) or TCP with TLS (RFC 5425).
//
// Frame layout:
//
//	<PRI>1 TIMESTAMP HOSTNAME correlic - MSGID [correlic@32473 ...] MSG
//
// HOSTNAME is the backend's host name (the originator), MSGID the event
// (incident.created, incident.escalated, test), the structured-data element
// carries the incident id, finding ids, severity, host, category, detection
// ids and MITRE techniques, and MSG is the JSON delivery payload. The MSG is
// sent without the RFC 5424 UTF-8 BOM, which several collectors would
// otherwise copy into the stored message.
//
// Like SMTP, the collector address is not run through the HTTP SSRF guard:
// syslog collectors are internal by nature. Endpoints need the admin role.
type SyslogSender struct {
	hostname string
	timeout  time.Duration
	now      func() time.Time
}

const (
	syslogAppName = "correlic"
	// syslogSDID is the structured-data element id. 32473 is the enterprise
	// number RFC 5424 reserves for documentation examples; Correlic has no
	// registered number.
	syslogSDID = "correlic@32473"
	// maxUDPFrame keeps a datagram under the IPv4 payload limit.
	maxUDPFrame = 65000
)

// NewSyslogSender creates a sender that stamps frames with this host's name.
func NewSyslogSender() *SyslogSender {
	host, _ := os.Hostname()
	return &SyslogSender{hostname: sanitizeSyslogToken(host, 255), timeout: outboundTimeout, now: time.Now}
}

// syslogSeverities maps Correlic severities to syslog severity codes.
var syslogSeverities = map[string]int{
	"critical": 2, // Critical
	"high":     3, // Error
	"medium":   4, // Warning
	"low":      5, // Notice
}

// Send builds the frame and writes it with the configured transport.
func (s *SyslogSender) Send(ctx context.Context, endpoint Endpoint, payload map[string]any) error {
	cfg := endpoint.Config
	host := getString(cfg, "host")
	if host == "" {
		return fmt.Errorf("syslog endpoint has no host configured")
	}
	protocol := getString(cfg, "protocol")
	if protocol == "" {
		protocol = SyslogUDP
	}
	port, _ := getInt(cfg, "port")
	if port <= 0 {
		port = defaultSyslogUDPPort
		if protocol == SyslogTCPTLS {
			port = defaultSyslogTLSPort
		}
	}
	facility, ok := syslogFacilities[getString(cfg, "facility")]
	if !ok {
		facility = syslogFacilities["local0"]
	}

	frame := buildSyslogFrame(facility, s.hostname, s.now().UTC(), payload)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := &net.Dialer{Timeout: outboundDialTimeout}

	var conn net.Conn
	var err error
	switch protocol {
	case SyslogUDP:
		if len(frame) > maxUDPFrame {
			return fmt.Errorf("syslog frame of %d bytes exceeds the UDP limit; use tcp", len(frame))
		}
		conn, err = d.DialContext(ctx, "udp", addr)
	case SyslogTCP:
		conn, err = d.DialContext(ctx, "tcp", addr)
	case SyslogTCPTLS:
		tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if getBool(cfg, "insecure_skip_verify") {
			tlsCfg.InsecureSkipVerify = true // explicitly opted in per endpoint
		}
		if caFile := getString(cfg, "ca_file"); caFile != "" {
			pool, perr := loadCertPool(caFile)
			if perr != nil {
				return fmt.Errorf("syslog ca_file: %w", perr)
			}
			tlsCfg.RootCAs = pool
		}
		td := &tls.Dialer{NetDialer: d, Config: tlsCfg}
		conn, err = td.DialContext(ctx, "tcp", addr)
	default:
		return fmt.Errorf("syslog endpoint has unsupported protocol %q", protocol)
	}
	if err != nil {
		return fmt.Errorf("syslog connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(s.now().Add(s.timeout))

	if protocol != SyslogUDP {
		// RFC 6587 octet counting: "<len> <frame>". Unambiguous for any
		// message content, unlike LF-terminated framing.
		frame = append([]byte(strconv.Itoa(len(frame))+" "), frame...)
	}
	if _, err := conn.Write(frame); err != nil {
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

// buildSyslogFrame renders one RFC 5424 message.
func buildSyslogFrame(facility int, hostname string, now time.Time, payload map[string]any) []byte {
	f := parseIncidentFields(payload)
	sev, ok := syslogSeverities[f.Severity]
	if !ok {
		sev = 6 // Informational (test messages, unknown severities)
	}
	pri := facility*8 + sev

	msgID := sanitizeSyslogToken(f.Event, 32)
	if hostname == "" {
		hostname = "-"
	}

	sd := strings.Builder{}
	sd.WriteString("[" + syslogSDID)
	sdParam := func(name, value string) {
		if value == "" {
			return
		}
		sd.WriteString(" " + name + `="` + escapeSDValue(value) + `"`)
	}
	sdParam("event", f.Event)
	sdParam("incident_id", f.ID)
	sdParam("severity", f.Severity)
	sdParam("host_id", f.HostID)
	sdParam("category", f.Category)
	sdParam("detection_ids", strings.Join(f.DetectionIDs, ","))
	inc, _ := payload["incident"].(map[string]any)
	sdParam("finding_ids", strings.Join(anyStrings(inc["finding_ids"]), ","))
	sdParam("finding_count", strconv.Itoa(f.FindingCount))
	sdParam("mitre", strings.Join(f.MITRE, ","))
	sd.WriteString("]")

	msg, err := json.Marshal(payload)
	if err != nil {
		msg = []byte(`{"error":"payload not serializable"}`)
	}

	var b strings.Builder
	b.WriteString("<" + strconv.Itoa(pri) + ">1 ")
	b.WriteString(now.Format("2006-01-02T15:04:05.000Z") + " ")
	b.WriteString(hostname + " " + syslogAppName + " - " + msgID + " ")
	b.WriteString(sd.String() + " ")
	b.Write(msg)
	return []byte(b.String())
}

// escapeSDValue escapes the three characters RFC 5424 reserves in PARAM-VALUE.
func escapeSDValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return r.Replace(v)
}

// sanitizeSyslogToken makes a header field RFC 5424 PRINTUSASCII without
// spaces, truncated to max; "-" (NILVALUE) when nothing is left.
func sanitizeSyslogToken(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
