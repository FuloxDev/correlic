package notification

import (
	"bufio"
	"context"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// smtpSession is what the minimal in-test SMTP server captured.
type smtpSession struct {
	from  string
	rcpts []string
	data  string
}

// startSMTPServer accepts exactly one SMTP session on a loopback port,
// speaks the minimum of ESMTP (EHLO, MAIL, RCPT, DATA, QUIT, no STARTTLS,
// no AUTH) and returns the port and a channel delivering the session.
func startSMTPServer(t *testing.T) (int, <-chan smtpSession) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan smtpSession, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		var sess smtpSession
		say("220 test.local ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				w.WriteString("250-test.local\r\n250-8BITMIME\r\n250 SIZE 1000000\r\n")
				w.Flush()
			case strings.HasPrefix(cmd, "HELO"):
				say("250 test.local")
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				sess.from = anglePath(line)
				say("250 OK")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				sess.rcpts = append(sess.rcpts, anglePath(line))
				say("250 OK")
			case cmd == "DATA":
				say("354 End data with <CR><LF>.<CR><LF>")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					b.WriteString(strings.TrimPrefix(l, ".")) // undo dot-stuffing
				}
				sess.data = b.String()
				say("250 OK queued")
			case cmd == "QUIT":
				say("221 Bye")
				out <- sess
				return
			default:
				say("500 unknown")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, out
}

// anglePath extracts the <path> of a MAIL FROM / RCPT TO line, ignoring
// ESMTP parameters such as BODY=8BITMIME.
func anglePath(line string) string {
	i, j := strings.IndexByte(line, '<'), strings.IndexByte(line, '>')
	if i < 0 || j < i {
		return strings.TrimSpace(line)
	}
	return line[i+1 : j]
}

func TestEmailSend(t *testing.T) {
	port, sessions := startSMTPServer(t)

	s := NewEmailSender().WithDashboardURL("https://correlic.example")
	s.now = func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }
	s.messageID = func() string { return "fixedid" }

	ep := Endpoint{ChannelType: ChannelEmail, Config: map[string]any{
		"smtp_host":      "127.0.0.1",
		"smtp_port":      port,
		"security":       EmailSecurityNone,
		"from":           "Correlic <alerts@example.com>",
		"to":             []any{"soc@example.com", "oncall@example.com"},
		"subject_prefix": "[prod]",
	}}
	if err := s.Send(context.Background(), ep, samplePayload("incident.created")); err != nil {
		t.Fatalf("send: %v", err)
	}

	var sess smtpSession
	select {
	case sess = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("smtp server saw no complete session")
	}
	if sess.from != "alerts@example.com" {
		t.Errorf("MAIL FROM = %q", sess.from)
	}
	if len(sess.rcpts) != 2 || sess.rcpts[0] != "soc@example.com" || sess.rcpts[1] != "oncall@example.com" {
		t.Errorf("RCPT TO = %v", sess.rcpts)
	}

	msg, err := mail.ReadMessage(strings.NewReader(sess.data))
	if err != nil {
		t.Fatalf("DATA is not a valid message: %v\n%s", err, sess.data)
	}
	dec := new(mime.WordDecoder)
	subject, _ := dec.DecodeHeader(msg.Header.Get("Subject"))
	if subject != "[prod] [Correlic] CRITICAL: AI agent read SSH private key" {
		t.Errorf("subject = %q", subject)
	}
	if msg.Header.Get("To") != "soc@example.com, oncall@example.com" {
		t.Errorf("To = %q", msg.Header.Get("To"))
	}
	if msg.Header.Get("X-Correlic-Incident") != "inc-123" || msg.Header.Get("Message-ID") != "<fixedid@correlic>" {
		t.Errorf("headers = %v", msg.Header)
	}
	if msg.Header.Get("Date") != "Fri, 09 Oct 2026 12:00:00 +0000" {
		t.Errorf("Date = %q", msg.Header.Get("Date"))
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("content-type = %q (%v)", msg.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var parts []string
	var bodies []string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		parts = append(parts, p.Header.Get("Content-Type"))
		raw := new(strings.Builder)
		qp := quotedprintable.NewReader(p)
		buf := make([]byte, 4096)
		for {
			n, err := qp.Read(buf)
			raw.Write(buf[:n])
			if err != nil {
				break
			}
		}
		bodies = append(bodies, raw.String())
	}
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "text/plain") || !strings.HasPrefix(parts[1], "text/html") {
		t.Fatalf("parts = %v", parts)
	}
	text, htmlBody := bodies[0], bodies[1]
	for _, want := range []string{
		"CRITICAL: AI agent read SSH private key",
		"Host:      host-a",
		"Rule:      ai.credential_access",
		"MITRE:     T1552, T1552.004",
		"Findings:  2",
		"Incident:  inc-123",
		"https://correlic.example/incidents/inc-123",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text part lacks %q:\n%s", want, text)
		}
	}
	if !strings.Contains(htmlBody, `href="https://correlic.example/incidents/inc-123"`) || !strings.Contains(htmlBody, "<td>host-a</td>") {
		t.Errorf("html part unexpected:\n%s", htmlBody)
	}
}

func TestEmailSendRequiresStartTLS(t *testing.T) {
	port, _ := startSMTPServer(t)
	s := NewEmailSender()
	ep := Endpoint{ChannelType: ChannelEmail, Config: map[string]any{
		"smtp_host": "127.0.0.1",
		"smtp_port": port,
		"security":  EmailSecurityStartTLS, // the test server does not offer it
		"from":      "alerts@example.com",
		"to":        []any{"soc@example.com"},
	}}
	err := s.Send(context.Background(), ep, samplePayload("test"))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected a STARTTLS error, got %v", err)
	}
}

func TestEmailSendConnectionRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	s := NewEmailSender()
	ep := Endpoint{ChannelType: ChannelEmail, Config: map[string]any{
		"smtp_host": "127.0.0.1", "smtp_port": port, "security": EmailSecurityNone,
		"from": "alerts@example.com", "to": []any{"soc@example.com"},
	}}
	err := s.Send(context.Background(), ep, samplePayload("test"))
	if err == nil || CategorizeSendError(err) != "connection refused" {
		t.Fatalf("expected connection refused, got %v (%q)", err, CategorizeSendError(err))
	}
}

func TestEmailHTMLEscapes(t *testing.T) {
	p := samplePayload("incident.created")
	p["incident"].(map[string]any)["title"] = `<script>alert("x")</script>`
	out := renderEmailHTML(parseIncidentFields(p), "")
	if strings.Contains(out, "<script>") {
		t.Fatal("incident text must be escaped in the HTML part")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("expected escaped title")
	}
}

func TestSanitizeHeader(t *testing.T) {
	if got := sanitizeHeader("a\r\nBcc: b"); got != "aBcc: b" {
		t.Fatalf("got %q", got)
	}
}
