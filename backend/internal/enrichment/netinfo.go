package enrichment

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type NetInfo struct {
	IP        string
	BGPPrefix string
	ASN       string
	ASNName   string
	Domain    string // reverse DNS
}

type cacheEntry struct {
	info    NetInfo
	cachedAt time.Time
}

type Enricher struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

func NewEnricher() *Enricher {
	return &Enricher{
		cache: make(map[string]cacheEntry),
	}
}

var GlobalEnricher = NewEnricher()

// GetNetInfo returns enrichment data for an IP, using an internal cache
// and Team Cymru's DNS service for extremely fast BGP/ASN lookups.
func (e *Enricher) GetNetInfo(ctx context.Context, ipStr string) NetInfo {
	return e.getNetInfo(ctx, ipStr, false, 800*time.Millisecond)
}

// GetNetInfoFresh bypasses cached empty results and uses a longer timeout.
// Use for user-initiated domain resolution where accuracy matters more than speed.
func (e *Enricher) GetNetInfoFresh(ctx context.Context, ipStr string) NetInfo {
	return e.getNetInfo(ctx, ipStr, true, 5*time.Second)
}

func (e *Enricher) getNetInfo(ctx context.Context, ipStr string, skipEmptyCache bool, timeout time.Duration) NetInfo {
	e.mu.RLock()
	entry, hit := e.cache[ipStr]
	e.mu.RUnlock()
	if hit {
		isEmpty := entry.info.ASN == "" && entry.info.Domain == ""
		// Return cached result unless: it's empty AND caller wants fresh AND it's older than 30s
		if !isEmpty || !skipEmptyCache {
			return entry.info
		}
		if time.Since(entry.cachedAt) < 30*time.Second && !skipEmptyCache {
			return entry.info
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		info := NetInfo{IP: ipStr}
		e.mu.Lock()
		e.cache[ipStr] = cacheEntry{info: info, cachedAt: time.Now()}
		e.mu.Unlock()
		return info
	}

	ctxDNS, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	var resDomain, resASN, resPrefix, resASNName string

	// Goroutine 1: Reverse DNS
	go func() {
		defer wg.Done()
		if names, err := net.DefaultResolver.LookupAddr(ctxDNS, ipStr); err == nil && len(names) > 0 {
			domain := names[0]
			if len(domain) > 0 && domain[len(domain)-1] == '.' {
				domain = domain[:len(domain)-1]
			}
			resDomain = domain
		}
	}()

	// Goroutine 2: Team Cymru IP -> ASN -> Org (IPv4 + IPv6)
	go func() {
		defer wg.Done()
		var originQuery string
		if ipv4 := ip.To4(); ipv4 != nil {
			originQuery = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ipv4[3], ipv4[2], ipv4[1], ipv4[0])
		} else if ip.To16() != nil {
			// IPv6: reverse nibble format for origin6.asn.cymru.com
			originQuery = ipv6CymruQuery(ip)
		}
		if originQuery == "" {
			return
		}

		if txts, err := net.DefaultResolver.LookupTXT(ctxDNS, originQuery); err == nil && len(txts) > 0 {
			parts := strings.Split(txts[0], "|")
			if len(parts) >= 2 {
				resASN = strings.TrimSpace(parts[0])
				resPrefix = strings.TrimSpace(parts[1])
			}
		}

		if resASN != "" {
			firstASN := strings.Split(resASN, " ")[0]
			queryASN := fmt.Sprintf("AS%s.asn.cymru.com", firstASN)
			if txts, err := net.DefaultResolver.LookupTXT(ctxDNS, queryASN); err == nil && len(txts) > 0 {
				parts := strings.Split(txts[0], "|")
				if len(parts) >= 5 {
					resASNName = strings.TrimSpace(parts[4])
				}
			}
		}
	}()

	wg.Wait()

	info := NetInfo{
		IP:        ipStr,
		Domain:    resDomain,
		ASN:       resASN,
		BGPPrefix: resPrefix,
		ASNName:   resASNName,
	}

	// Cache the result. Empty results are cached to prevent DNS spam,
	// but GetNetInfoFresh can bypass empty cache entries.
	e.mu.Lock()
	e.cache[ipStr] = cacheEntry{info: info, cachedAt: time.Now()}
	e.mu.Unlock()

	return info
}

// ipv6CymruQuery builds the reverse-nibble DNS query for Team Cymru's IPv6 origin service.
// Example: 2606:4700::1 → 1.0.0.0...0.0.7.4.6.0.6.2.origin6.asn.cymru.com
func ipv6CymruQuery(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	// Expand to 32 hex nibbles, reverse, dot-separate
	nibbles := make([]byte, 0, 63) // 32 nibbles + 31 dots
	for i := 15; i >= 0; i-- {
		lo := ip[i] & 0x0f
		hi := ip[i] >> 4
		if len(nibbles) > 0 {
			nibbles = append(nibbles, '.')
		}
		nibbles = append(nibbles, "0123456789abcdef"[lo])
		nibbles = append(nibbles, '.')
		nibbles = append(nibbles, "0123456789abcdef"[hi])
	}
	return string(nibbles) + ".origin6.asn.cymru.com"
}
