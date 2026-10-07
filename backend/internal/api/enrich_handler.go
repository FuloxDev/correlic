package api

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/enrichment"
)

// ResolveIP handles POST /api/v1/enrich/ip
// Body: { "ip": "1.2.3.4" }
// Returns reverse DNS, ASN, BGP prefix for the given IP address.
func ResolveIP(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if body.IP == "" {
		BadRequest(w, "ip is required")
		return
	}
	if net.ParseIP(body.IP) == nil {
		BadRequest(w, "invalid IP address")
		return
	}

	info := enrichment.GlobalEnricher.GetNetInfoFresh(r.Context(), body.IP)

	domain := info.Domain
	if isGenericPTR(domain) {
		domain = ""
	}

	// Try to infer domain from ASN name if reverse DNS didn't work
	source := ""
	if domain != "" {
		source = "reverse_dns"
	} else if info.ASNName != "" {
		if inferred := inferDomainFromASN(info.ASNName); inferred != "" {
			domain = inferred
			source = "asn_inferred"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ip":          body.IP,
		"domain":      domain,
		"source":      source,
		"asn_name":    info.ASNName,
		"asn":         info.ASN,
		"bgp_prefix":  info.BGPPrefix,
		"reverse_dns": info.Domain,
	})
}

type ipResult struct {
	IP         string `json:"ip"`
	Domain     string `json:"domain"`
	Source     string `json:"source"`
	ASNName    string `json:"asn_name"`
	ASN        string `json:"asn"`
	BGPPrefix  string `json:"bgp_prefix"`
	ReverseDNS string `json:"reverse_dns"`
}

func enrichIP(info enrichment.NetInfo, ip string) ipResult {
	domain := info.Domain
	if isGenericPTR(domain) {
		domain = ""
	}
	source := ""
	if domain != "" {
		source = "reverse_dns"
	} else if info.ASNName != "" {
		if inferred := inferDomainFromASN(info.ASNName); inferred != "" {
			domain = inferred
			source = "asn_inferred"
		}
	}
	return ipResult{
		IP:         ip,
		Domain:     domain,
		Source:     source,
		ASNName:    info.ASNName,
		ASN:        info.ASN,
		BGPPrefix:  info.BGPPrefix,
		ReverseDNS: info.Domain,
	}
}

// ResolveBulkIPs handles POST /api/v1/enrich/ips
// Body: { "ips": ["1.2.3.4", "5.6.7.8"] }
// Returns enrichment for up to 50 IPs in one call.
// All lookups run concurrently using cached results (800ms timeout).
func ResolveBulkIPs(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if len(body.IPs) == 0 {
		BadRequest(w, "ips array is required")
		return
	}
	if len(body.IPs) > 50 {
		BadRequest(w, "maximum 50 IPs per request")
		return
	}

	// Validate and deduplicate
	valid := make([]string, 0, len(body.IPs))
	seen := make(map[string]bool, len(body.IPs))
	for _, ip := range body.IPs {
		if net.ParseIP(ip) == nil || seen[ip] {
			continue
		}
		seen[ip] = true
		valid = append(valid, ip)
	}

	// Resolve all IPs concurrently using the fast cached enricher (800ms timeout)
	results := make([]ipResult, len(valid))
	var wg sync.WaitGroup
	wg.Add(len(valid))
	for i, ip := range valid {
		go func(idx int, ipAddr string) {
			defer wg.Done()
			info := enrichment.GlobalEnricher.GetNetInfo(r.Context(), ipAddr)
			results[idx] = enrichIP(info, ipAddr)
		}(i, ip)
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"results": results,
	})
}
