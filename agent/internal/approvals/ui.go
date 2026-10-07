package approvals

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/transport"
)

// LocalUI serves a minimal local approvals page so a developer can approve/reject with one click.
// It is intentionally "local only" (binds 127.0.0.1).
type LocalUI struct {
	Transport transport.Transport
	AgentID   string
	Addr      string // e.g. "127.0.0.1:8787"
}

func (u *LocalUI) Start(ctx context.Context) {
	if u.Transport == nil || u.AgentID == "" {
		slog.Warn("approvals UI disabled (missing dependencies)")
		return
	}
	addr := u.Addr
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:8787"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/approvals", u.handleApprovals)
	mux.HandleFunc("/approve", u.handleDecide("approved"))
	mux.HandleFunc("/reject", u.handleDecide("rejected"))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Warn("approvals UI listen failed", "addr", addr, "error", err)
		return
	}
	slog.Info("approvals UI listening", "addr", addr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		slog.Warn("approvals UI server error", "error", err)
	}
}

func (u *LocalUI) BaseURL() string {
	addr := u.Addr
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:8787"
	}
	return "http://" + addr + "/approvals"
}

func (u *LocalUI) handleApprovals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	items, err := u.Transport.ListApprovals(ctx, "pending", u.AgentID, 50)
	if err != nil {
		http.Error(w, "failed to fetch approvals", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintln(w, "<html><body>")
	_, _ = fmt.Fprintln(w, "<h2>Correlic Approvals (pending)</h2>")
	if len(items) == 0 {
		_, _ = fmt.Fprintln(w, "<p>No pending approvals.</p>")
		_, _ = fmt.Fprintln(w, "</body></html>")
		return
	}
	_, _ = fmt.Fprintln(w, "<ul>")
	for _, a := range items {
		summary := htmlEscape(approvalSummary(a))
		aid := url.QueryEscape(a.ID)
		_, _ = fmt.Fprintf(
			w,
			"<li><b>%s</b> (id=%s) <a href=\"/approve?id=%s\">Approve</a> | <a href=\"/reject?id=%s\">Reject</a></li>\n",
			summary, htmlEscape(a.ID), aid, aid,
		)
		// Include JSON subject for debugging.
		if len(a.Subject) > 0 {
			var pretty any
			if err := json.Unmarshal(a.Subject, &pretty); err == nil {
				b, _ := json.MarshalIndent(pretty, "", "  ")
				_, _ = fmt.Fprintf(w, "<pre>%s</pre>\n", htmlEscape(string(b)))
			}
		}
	}
	_, _ = fmt.Fprintln(w, "</ul>")
	_, _ = fmt.Fprintln(w, "</body></html>")
}

func (u *LocalUI) handleDecide(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if err := u.Transport.DecideApproval(r.Context(), id, status, "local-ui"); err != nil {
			http.Error(w, "failed to decide approval", http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
	}
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

