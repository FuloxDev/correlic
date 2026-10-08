package notification

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

// useFakeResolver swaps the package resolver for a deterministic one so
// tests never touch real DNS.
func useFakeResolver(t *testing.T) {
	t.Helper()
	orig := lookupIP
	lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "public.example":
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		case "public6.example":
			return []net.IPAddr{{IP: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}}, nil
		case "internal.example":
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
		case "mixed.example":
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}}, nil
		case "metadata.example":
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		default:
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
	}
	t.Cleanup(func() { lookupIP = orig })
}

func TestValidateOutboundURL(t *testing.T) {
	useFakeResolver(t)

	cases := []struct {
		name string
		raw  string
		want error // nil, ErrInvalidURL or ErrBlockedDestination; "dns" handled separately
	}{
		{"public host", "https://public.example/hook", nil},
		{"public ipv6 host", "https://public6.example/hook", nil},
		{"public ip literal", "http://93.184.216.34:8080/x", nil},

		{"loopback v4", "http://127.0.0.1/hook", ErrBlockedDestination},
		{"loopback v4 range", "http://127.5.6.7/hook", ErrBlockedDestination},
		{"loopback v6", "http://[::1]:8080/hook", ErrBlockedDestination},
		{"metadata link-local", "http://169.254.169.254/latest/meta-data/", ErrBlockedDestination},
		{"metadata via dns", "http://metadata.example/", ErrBlockedDestination},
		{"link-local v6", "http://[fe80::1]/", ErrBlockedDestination},
		{"rfc1918 10/8", "https://10.1.2.3/x", ErrBlockedDestination},
		{"rfc1918 172.16/12", "https://172.16.0.1/x", ErrBlockedDestination},
		{"rfc1918 192.168/16", "https://192.168.1.1/x", ErrBlockedDestination},
		{"ula v6", "https://[fd00::1]/x", ErrBlockedDestination},
		{"unspecified v4", "http://0.0.0.0/", ErrBlockedDestination},
		{"unspecified v6", "http://[::]/", ErrBlockedDestination},
		{"multicast", "http://224.0.0.1/", ErrBlockedDestination},
		{"v4-mapped loopback", "http://[::ffff:127.0.0.1]/", ErrBlockedDestination},
		{"localhost", "https://localhost/x", ErrBlockedDestination},
		{"localhost subdomain", "https://foo.localhost:3000/x", ErrBlockedDestination},
		{"localhost case", "https://LOCALHOST/x", ErrBlockedDestination},
		{"private via dns", "https://internal.example/", ErrBlockedDestination},
		{"mixed answer", "https://mixed.example/", ErrBlockedDestination},

		{"empty", "", ErrInvalidURL},
		{"garbage", "not a url", ErrInvalidURL},
		{"ftp scheme", "ftp://public.example/", ErrInvalidURL},
		{"file scheme", "file:///etc/passwd", ErrInvalidURL},
		{"missing host", "https:///path", ErrInvalidURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOutboundURL(tc.raw)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateOutboundURL(%q) = %v, want nil", tc.raw, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("ValidateOutboundURL(%q) = %v, want %v", tc.raw, err, tc.want)
			}
		})
	}
}

func TestValidateOutboundURL_DNSFailure(t *testing.T) {
	useFakeResolver(t)
	err := ValidateOutboundURL("https://nxdomain.example/")
	if err == nil {
		t.Fatalf("expected error")
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected DNSError, got %v", err)
	}
	if got := CategorizeSendError(err); got != "dns" {
		t.Fatalf("category=%q want dns", got)
	}
}

func TestSendersRefuseLoopbackAtSendTime(t *testing.T) {
	// A real server on loopback must never be reached, even though it exists.
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()

	ctx := context.Background()
	wh := NewWebhookSender()
	err := wh.Send(ctx, Endpoint{Config: map[string]any{"url": srv.URL}}, map[string]any{"event": "test"})
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("webhook: err=%v want blocked destination", err)
	}
	sl := NewSlackSender()
	err = sl.Send(ctx, Endpoint{Config: map[string]any{"webhook_url": srv.URL}}, map[string]any{"event": "test"})
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("slack: err=%v want blocked destination", err)
	}
	if hit {
		t.Fatalf("loopback server was contacted")
	}
}

func TestOutboundDialerRefusesLoopbackEvenIfValidationSkipped(t *testing.T) {
	// Exercise the transport directly: the dial-time check must hold on its own.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	client := newOutboundClient()
	_, err := client.Get(srv.URL)
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("err=%v want blocked destination", err)
	}
}

func TestOutboundClientDoesNotFollowRedirects(t *testing.T) {
	client := newOutboundClient()
	if client.CheckRedirect == nil {
		t.Fatalf("CheckRedirect not set")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://public.example/", nil)
	if err := client.CheckRedirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	if client.Timeout <= 0 || client.Timeout > outboundTimeout {
		t.Fatalf("timeout=%v", client.Timeout)
	}
}

func TestApplyCustomHeadersDropsFramingHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://public.example/", strings.NewReader("{}"))
	applyCustomHeaders(req, map[string]any{
		"Host":              "evil.internal",
		"content-length":    "1",
		"Transfer-Encoding": "chunked",
		"CONNECTION":        "close",
		"X-Custom":          "ok",
		"X-Number":          42, // non-string values are ignored
	})
	if req.Host == "evil.internal" || req.Header.Get("Host") != "" {
		t.Fatalf("Host override applied")
	}
	for _, h := range []string{"Content-Length", "Transfer-Encoding", "Connection"} {
		if req.Header.Get(h) != "" {
			t.Fatalf("%s override applied", h)
		}
	}
	if req.Header.Get("X-Custom") != "ok" {
		t.Fatalf("X-Custom not applied")
	}
	if req.Header.Get("X-Number") != "" {
		t.Fatalf("non-string header applied")
	}
}

func TestCategorizeSendError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{&HTTPStatusError{Status: 502}, "http 502"},
		{errors.Join(errors.New("wrapped"), &HTTPStatusError{Status: 404}), "http 404"},
		{ErrBlockedDestination, "blocked destination"},
		{ErrInvalidURL, "invalid url"},
		{&net.DNSError{Err: "nx"}, "dns"},
		{context.DeadlineExceeded, "timeout"},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "connection refused"},
		{errors.New("something else with 10.0.0.1 in it"), "request failed"},
	}
	for _, tc := range cases {
		if got := CategorizeSendError(tc.err); got != tc.want {
			t.Errorf("CategorizeSendError(%v) = %q want %q", tc.err, got, tc.want)
		}
	}
}
