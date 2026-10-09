package notification

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/secrets"
)

// EmailSender delivers notifications over SMTP (net/smtp) as a
// multipart/alternative message: a plain-text part and a minimal HTML part.
//
// Connection security follows the endpoint's "security" setting:
//   - "starttls" (default): plain TCP, then STARTTLS; the server MUST offer it
//     or delivery fails (no silent downgrade);
//   - "tls": implicit TLS from the first byte (SMTPS, usually port 465);
//   - "none": cleartext; a username is only accepted for a localhost relay
//     since net/smtp refuses PLAIN auth on an unencrypted connection.
//
// The SMTP host is deliberately not run through the HTTP SSRF guard: mail
// relays are normally internal, and the protocol is not a general-purpose
// request primitive. Creating or changing an endpoint needs the admin role.
type EmailSender struct {
	cipher       *secrets.Cipher
	dashboardURL string
	// timeout bounds the whole SMTP session (dial, handshake, DATA, QUIT).
	timeout time.Duration
	// now and messageID are swappable for deterministic tests.
	now       func() time.Time
	messageID func() string
}

// emailSessionTimeout bounds one delivery end to end.
const emailSessionTimeout = 20 * time.Second

// NewEmailSender creates an email sender with the default session timeout.
func NewEmailSender() *EmailSender {
	return &EmailSender{
		timeout:   emailSessionTimeout,
		now:       time.Now,
		messageID: randomMessageID,
	}
}

// WithCipher sets the cipher used to open the sealed SMTP password.
func (s *EmailSender) WithCipher(c *secrets.Cipher) *EmailSender {
	s.cipher = c
	return s
}

// WithDashboardURL sets the dashboard base URL used for the incident link.
func (s *EmailSender) WithDashboardURL(base string) *EmailSender {
	s.dashboardURL = strings.TrimRight(base, "/")
	return s
}

// Send renders the payload and submits it to the configured SMTP server.
func (s *EmailSender) Send(ctx context.Context, endpoint Endpoint, payload map[string]any) error {
	cfg := endpoint.Config
	host := getString(cfg, "smtp_host")
	if host == "" {
		return fmt.Errorf("email endpoint has no smtp_host configured")
	}
	port, _ := getInt(cfg, "smtp_port")
	if port <= 0 {
		port = defaultSMTPPort
	}
	security := getString(cfg, "security")
	if security == "" {
		security = EmailSecurityStartTLS
	}
	from := getString(cfg, "from")
	fromAddr, err := mail.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("email endpoint 'from' invalid: %w", err)
	}
	to, err := getStringList(cfg, "to")
	if err != nil || len(to) == 0 {
		return fmt.Errorf("email endpoint has no 'to' recipients configured")
	}
	username := getString(cfg, "username")
	password, err := ResolveSecret(s.cipher, cfg, "password")
	if err != nil {
		return fmt.Errorf("email endpoint password: %w", err)
	}

	msg := s.buildMessage(from, to, getString(cfg, "subject_prefix"), payload)

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	conn, err := s.dial(ctx, host, port, security)
	if err != nil {
		return fmt.Errorf("smtp connect: %w", err)
	}
	defer conn.Close()
	deadline := s.now().Add(s.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer c.Close()

	if security == EmailSecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp server %s does not offer STARTTLS (set security to 'tls' or 'none' explicitly)", host)
		}
		if err := c.StartTLS(s.tlsConfig(host)); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return fmt.Errorf("smtp server %s does not offer AUTH but a username is configured", host)
		}
		if err := c.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(fromAddr.Address); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		addr, err := mail.ParseAddress(rcpt)
		if err != nil {
			return fmt.Errorf("email endpoint recipient invalid: %w", err)
		}
		if err := c.Rcpt(addr.Address); err != nil {
			return fmt.Errorf("smtp RCPT TO: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp DATA write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp DATA end: %w", err)
	}
	if err := c.Quit(); err != nil {
		// The message was accepted at end-of-DATA; a failed QUIT is not a
		// delivery failure.
		return nil
	}
	return nil
}

// dial opens the transport connection according to the security mode.
func (s *EmailSender) dial(ctx context.Context, host string, port int, security string) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := &net.Dialer{Timeout: outboundDialTimeout}
	if security == EmailSecurityTLS {
		td := &tls.Dialer{NetDialer: d, Config: s.tlsConfig(host)}
		return td.DialContext(ctx, "tcp", addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

func (s *EmailSender) tlsConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

// buildMessage renders the RFC 5322 message (CRLF line endings; net/smtp's
// DATA writer handles dot-stuffing).
func (s *EmailSender) buildMessage(from string, to []string, subjectPrefix string, payload map[string]any) []byte {
	f := parseIncidentFields(payload)
	link := incidentURL(s.dashboardURL, f.ID)

	subject := "[Correlic] " + f.headline()
	if p := strings.TrimSpace(subjectPrefix); p != "" {
		subject = p + " " + subject
	}
	subject = sanitizeHeader(truncate(subject, 200))

	boundary := "correlic-" + s.messageID()
	var b bytes.Buffer
	writeHeader := func(name, value string) {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\r\n")
	}
	writeHeader("From", sanitizeHeader(from))
	writeHeader("To", sanitizeHeader(strings.Join(to, ", ")))
	writeHeader("Subject", mime.QEncoding.Encode("utf-8", subject))
	writeHeader("Date", s.now().UTC().Format(time.RFC1123Z))
	writeHeader("Message-ID", "<"+s.messageID()+"@correlic>")
	writeHeader("X-Correlic-Event", sanitizeHeader(f.Event))
	writeHeader("X-Correlic-Incident", sanitizeHeader(f.ID))
	writeHeader("X-Correlic-Severity", sanitizeHeader(f.Severity))
	writeHeader("Auto-Submitted", "auto-generated")
	writeHeader("MIME-Version", "1.0")
	writeHeader("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")

	writePart(&b, boundary, "text/plain; charset=UTF-8", renderEmailText(f, link))
	writePart(&b, boundary, "text/html; charset=UTF-8", renderEmailHTML(f, link))
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

// writePart appends one quoted-printable MIME part.
func writePart(b *bytes.Buffer, boundary, contentType, body string) {
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: " + contentType + "\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	_ = qp.Close()
	b.WriteString("\r\n")
}

// renderEmailText is the plain-text alternative.
func renderEmailText(f incidentFields, link string) string {
	var sb strings.Builder
	sb.WriteString(f.headline() + "\n\n")
	if f.Summary != "" {
		sb.WriteString(f.Summary + "\n\n")
	}
	sb.WriteString("Severity:  " + strings.ToUpper(f.Severity) + "\n")
	sb.WriteString("Host:      " + orDash(f.HostID) + "\n")
	if rule := ruleLabel(f); rule != "" {
		sb.WriteString("Rule:      " + rule + "\n")
	}
	if len(f.MITRE) > 0 {
		sb.WriteString("MITRE:     " + strings.Join(f.MITRE, ", ") + "\n")
	}
	sb.WriteString(fmt.Sprintf("Findings:  %d\n", f.FindingCount))
	sb.WriteString("Incident:  " + orDash(f.ID) + "\n")
	if f.StartedAt != "" {
		sb.WriteString("Started:   " + f.StartedAt + "\n")
	}
	if link != "" {
		sb.WriteString("\nOpen in Correlic: " + link + "\n")
	}
	sb.WriteString("\n-- \nSent by Correlic. Severity threshold and recipients are set under Settings > Notifications.\n")
	return sb.String()
}

// renderEmailHTML is a minimal, inline-styled HTML alternative. Every value
// is escaped; nothing from the incident is interpreted as markup.
func renderEmailHTML(f incidentFields, link string) string {
	esc := html.EscapeString
	color := map[string]string{"critical": "#e02424", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}[f.Severity]
	if color == "" {
		color = "#94a3b8"
	}
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;color:#111">`)
	sb.WriteString(`<h2 style="margin:0 0 8px 0;border-left:4px solid ` + color + `;padding-left:8px">` + esc(f.headline()) + `</h2>`)
	if f.Summary != "" {
		sb.WriteString(`<p style="margin:0 0 12px 0">` + esc(f.Summary) + `</p>`)
	}
	sb.WriteString(`<table cellpadding="4" cellspacing="0" style="border-collapse:collapse">`)
	row := func(k, v string) {
		sb.WriteString(`<tr><td style="color:#555;padding-right:12px">` + esc(k) + `</td><td>` + esc(v) + `</td></tr>`)
	}
	row("Severity", strings.ToUpper(f.Severity))
	row("Host", orDash(f.HostID))
	if rule := ruleLabel(f); rule != "" {
		row("Rule", rule)
	}
	if len(f.MITRE) > 0 {
		row("MITRE ATT&CK", strings.Join(f.MITRE, ", "))
	}
	row("Findings", strconv.Itoa(f.FindingCount))
	row("Incident", orDash(f.ID))
	if f.StartedAt != "" {
		row("Started", f.StartedAt)
	}
	sb.WriteString(`</table>`)
	if link != "" {
		sb.WriteString(`<p style="margin:16px 0"><a href="` + esc(link) + `" style="background:#0ea5e9;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none">Open in Correlic</a></p>`)
	}
	sb.WriteString(`<p style="color:#777;font-size:12px">Sent by Correlic.</p></body></html>`)
	return sb.String()
}

// sanitizeHeader strips characters that would end or fold a header line.
func sanitizeHeader(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func randomMessageID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}
