package notification

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// Sentinel errors for outbound destination checks.
var (
	// ErrInvalidURL means the configured URL could not be parsed or uses an
	// unsupported scheme.
	ErrInvalidURL = errors.New("invalid url")
	// ErrBlockedDestination means the URL resolves to an address that must
	// never be contacted from the backend (loopback, private, link-local,
	// unspecified or multicast ranges, or a localhost name).
	ErrBlockedDestination = errors.New("destination not allowed")
)

// HTTPStatusError is returned when the remote endpoint answered with a
// non-success status.
type HTTPStatusError struct {
	Status int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("http %d", e.Status)
}

const (
	outboundTimeout     = 10 * time.Second
	outboundDialTimeout = 5 * time.Second
	outboundDNSTimeout  = 5 * time.Second
)

// lookupIP resolves a host name. It is a variable so tests can substitute a
// deterministic resolver.
var lookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// ValidateOutboundURL checks that raw is an http(s) URL whose host resolves
// exclusively to public addresses. It is the SSRF guard for notification
// endpoints and must be called when an endpoint is created, updated or
// tested, and again immediately before each delivery (DNS can change).
func ValidateOutboundURL(raw string) error {
	ctx, cancel := context.WithTimeout(context.Background(), outboundDNSTimeout)
	defer cancel()
	return validateOutboundURL(ctx, raw)
}

func validateOutboundURL(ctx context.Context, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%w: empty", ErrInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidURL)
	}
	if _, err := resolveAllowed(ctx, host); err != nil {
		return err
	}
	return nil
}

// isLocalhostName reports whether host names the local machine by name.
func isLocalhostName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// isDisallowedIP reports whether ip falls in a range the backend must never
// contact on behalf of a tenant.
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() || // RFC 1918 and fc00::/7
		ip.IsLinkLocalUnicast() || // 169.254/16 and fe80::/10
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// resolveAllowed resolves host and returns its addresses, or an error if the
// name is a localhost alias, cannot be resolved, or any address is in a
// disallowed range. Rejecting on any bad address (rather than filtering)
// prevents DNS answers that mix public and internal records from slipping
// through.
func resolveAllowed(ctx context.Context, host string) ([]net.IP, error) {
	if isLocalhostName(host) {
		return nil, fmt.Errorf("%w: localhost", ErrBlockedDestination)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if isDisallowedIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
		}
		return []net.IP{ip}, nil
	}
	addrs, err := lookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dns lookup failed: %w", &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true})
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if isDisallowedIP(a.IP) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlockedDestination, host, a.IP)
		}
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// newOutboundClient builds the HTTP client used for webhook and Slack
// delivery:
//
//   - 10 s overall timeout;
//   - no redirects (a 3xx is returned to the caller and treated as failure),
//     so a public endpoint cannot bounce us to an internal address;
//   - the dialer re-resolves the host and refuses disallowed addresses at
//     connect time, closing the window between validation and delivery
//     (DNS rebinding);
//   - no egress proxy: deliveries go straight to the destination so the
//     address check is authoritative.
func newOutboundClient() *http.Client {
	dialer := &net.Dialer{Timeout: outboundDialTimeout}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
			}
			ips, err := resolveAllowed(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSHandshakeTimeout:   outboundDialTimeout,
		ResponseHeaderTimeout: outboundTimeout,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   outboundTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// forbiddenCustomHeaders are request headers an endpoint's custom header map
// may not override: they control framing and routing of the request itself.
var forbiddenCustomHeaders = map[string]struct{}{
	"host":              {},
	"content-length":    {},
	"transfer-encoding": {},
	"connection":        {},
}

// applyCustomHeaders copies string-valued entries of headers onto req,
// skipping names in forbiddenCustomHeaders.
func applyCustomHeaders(req *http.Request, headers map[string]any) {
	for k, v := range headers {
		name := strings.TrimSpace(k)
		if name == "" {
			continue
		}
		if _, forbidden := forbiddenCustomHeaders[strings.ToLower(name)]; forbidden {
			continue
		}
		if s, ok := v.(string); ok {
			req.Header.Set(name, s)
		}
	}
}

// CategorizeSendError reduces a delivery error to a short, non-sensitive
// category suitable for returning to API clients. Full details stay in the
// server log.
func CategorizeSendError(err error) string {
	if err == nil {
		return ""
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Error()
	}
	if errors.Is(err, ErrBlockedDestination) {
		return "blocked destination"
	}
	if errors.Is(err, ErrInvalidURL) {
		return "invalid url"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection refused"
	}
	return "request failed"
}
