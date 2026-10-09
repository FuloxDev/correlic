package notification

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

type netConn = net.Conn

// dialTestServer connects to srv regardless of the requested address.
func dialTestServer(ctx context.Context, network string, srv *httptest.Server) (net.Conn, error) {
	d := &net.Dialer{}
	return d.DialContext(ctx, network, strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://"))
}

// lookupIPAlias extends the fake resolver installed by useFakeResolver with
// one more public answer.
func lookupIPAlias(t *testing.T, host, ip string) {
	t.Helper()
	prev := lookupIP
	lookupIP = func(ctx context.Context, h string) ([]net.IPAddr, error) {
		if h == host {
			return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
		}
		return prev(ctx, h)
	}
	t.Cleanup(func() { lookupIP = prev })
}
