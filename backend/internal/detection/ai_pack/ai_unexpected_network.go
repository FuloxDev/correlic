package ai_pack

import (
	"fmt"
	"net"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/enrichment"
	"github.com/correlic/correlic-backend/internal/event"
)

// standardAIPorts are ports commonly used by AI service APIs.
var standardAIPorts = map[int]bool{
	80:   true, // HTTP
	443:  true, // HTTPS
	8080: true, // HTTP alt
	8443: true, // HTTPS alt
}

var internalDatabasePorts = map[int]bool{
	5432:  true, // postgres
	3306:  true, // mysql
	27017: true, // mongodb
	6379:  true, // redis
	9200:  true, // elasticsearch
	9042:  true, // cassandra
	26257: true, // cockroachdb
}

// internalInfraPorts are infrastructure services that AI agents should not directly access.
var internalInfraPorts = map[int]bool{
	6443: true, // Kubernetes API server
	2379: true, // etcd client
	2380: true, // etcd peer
	8500: true, // Consul
	8200: true, // HashiCorp Vault
	389:  true, // LDAP
	636:  true, // LDAPS
}

// internalCriticalPorts are unencrypted admin APIs — always critical when accessed by AI.
var internalCriticalPorts = map[int]bool{
	2375: true, // Docker API (unencrypted!) — full container control
	2376: true, // Docker API (TLS)
}

// AIUnexpectedNetwork detects when an AI agent connects to external IPs that
// are not on the safe domain list. Non-standard ports get higher severity;
// standard ports (443/80) to unknown domains get lower severity but are still
// tracked since malicious C2 commonly uses port 443 to blend in.
type AIUnexpectedNetwork struct{}

func (d *AIUnexpectedNetwork) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.unexpected_network",
		Pack:            "ai",
		Name:            "AI Unexpected Network Connection",
		Severity:        "high",
		Description:     "AI agent connected to an external IP not on the safe domain list",
		Tags:            []string{"ai", "network", "external"},
		MITRETechniques: []string{"T1071", "T1571"},
	}
}

func (d *AIUnexpectedNetwork) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"net_connect"},
		WindowSecs: 0,
	}
}

func (d *AIUnexpectedNetwork) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil || evt.Target == nil || evt.Target.IP == "" {
		return nil
	}

	// Check if the process belongs to an AI agent tree
	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	dstIP := evt.Target.IP
	dstPort := evt.Target.Port

	// Internal/private traffic is generally skipped except high-risk internal targets.
	if isPrivateIP(dstIP) {
		if finding := buildHighRiskInternalFinding(evt, aiType, dstIP, dstPort); finding != nil {
			return []detection.Finding{*finding}
		}
		return nil
	}

	// Resolve domain BEFORE port-based decisions — domain reputation is more
	// important than port number. Malicious C2, exfiltration, and reverse shells
	// commonly use port 443 to blend in with legitimate HTTPS traffic.
	info := enrichment.GlobalEnricher.GetNetInfo(ctx.Ctx, dstIP)
	domain := info.Domain

	// Correlate with recent DNS queries from the same PID for a better domain name.
	var dnsDomain string
	if ctx.DNSCache != nil && evt.Process != nil {
		dnsDomain = ctx.DNSCache.Lookup(evt.Process.PID, evt.Timestamp)
	}
	if dnsDomain != "" && (domain == "" || isGenericPTR(domain)) {
		domain = dnsDomain
	}

	// Suppress connections to explicitly safe domains (regardless of port).
	if domain != "" && ctx.SafeDomainChecker != nil && ctx.SafeDomainChecker.IsSafe(domain) {
		return nil
	}
	if dnsDomain != "" && dnsDomain != domain && ctx.SafeDomainChecker != nil && ctx.SafeDomainChecker.IsSafe(dnsDomain) {
		return nil
	}

	// Standard web ports with a known domain that passed safe-domain check:
	// lower severity since it's likely legitimate but unrecognised traffic.
	isStandardPort := standardAIPorts[dstPort]

	// Group pattern by BGP prefix or fallback to CIDR /24
	patternIP := dstIP
	if info.BGPPrefix != "" {
		patternIP = info.BGPPrefix
	} else {
		ip := net.ParseIP(dstIP)
		if ip != nil && ip.To4() != nil {
			ip = ip.To4()
			patternIP = fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
		}
	}
	pattern := fmt.Sprintf("%s:%d", patternIP, dstPort)

	summary := fmt.Sprintf("%s connected to subnet %s (port %d)", aiType, patternIP, dstPort)
	if info.ASNName != "" && domain != "" {
		summary = fmt.Sprintf("%s connected to %s on %s (subnet %s, port %d)", aiType, domain, info.ASNName, patternIP, dstPort)
	} else if info.ASNName != "" {
		summary = fmt.Sprintf("%s connected to %s (subnet %s, port %d)", aiType, info.ASNName, patternIP, dstPort)
	} else if domain != "" {
		summary = fmt.Sprintf("%s connected to %s (subnet %s, port %d)", aiType, domain, patternIP, dstPort)
	}

	// Confidence and severity depend on port type and enrichment data.
	// Non-standard ports are more suspicious than standard web ports.
	confidence := 0.65
	severity := "medium"
	if isStandardPort {
		// Standard port (443/80) to unknown domain — lower severity, could be
		// legitimate traffic to an unrecognised API or a C2 channel.
		confidence = 0.40
		severity = "low"
	}
	if info.ASNName != "" {
		confidence += 0.15
		if !isStandardPort {
			severity = "high"
		}
	}

	fctx := map[string]any{
		"ai_type":     aiType,
		"dst_ip":      dstIP,
		"dst_port":    dstPort,
		"domain":      domain,
		"pid":         evt.Process.PID,
		"comm":        evt.Process.Comm,
		"signal_type": "network_dest",
		"pattern":     pattern,
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}
	if info.ASNName != "" {
		fctx["asn_name"] = info.ASNName
	}
	if info.ASN != "" {
		fctx["asn"] = info.ASN
	}
	if info.BGPPrefix != "" {
		fctx["bgp_prefix"] = info.BGPPrefix
	}
	if dnsDomain != "" {
		fctx["dns_domain"] = dnsDomain
	}

	// Per-finding MITRE based on port type.
	if isStandardPort {
		fctx["mitre_techniques"] = []string{"T1071.001"} // Web Protocols
	} else {
		fctx["mitre_techniques"] = []string{"T1571"} // Non-Standard Port
	}

	return []detection.Finding{
		{
			Title:      "AI agent made unexpected external connection",
			Summary:    summary,
			Severity:   severity,
			Confidence: confidence,
			Context:    fctx,
		},
	}
}

func buildHighRiskInternalFinding(evt *event.Event, aiType, dstIP string, dstPort int) *detection.Finding {
	var finding *detection.Finding

	switch {
	case dstIP == "169.254.169.254":
		finding = &detection.Finding{
			Severity:   "critical",
			Confidence: 0.95,
			Title:      "AI agent accessed cloud metadata service",
			Summary:    fmt.Sprintf("%s connected to internal metadata service %s:%d", aiType, dstIP, dstPort),
			Context: map[string]any{
				"ai_type":         aiType,
				"dst_ip":          dstIP,
				"dst_port":        dstPort,
				"pid":             evt.Process.PID,
				"comm":            evt.Process.Comm,
				"internal_threat":  "metadata_service",
				"signal_type":     "network_dest",
				"pattern":         fmt.Sprintf("%s:%d", dstIP, dstPort),
				"mitre_techniques": []string{"T1552.005"}, // Cloud Instance Metadata API
			},
		}
	case (dstPort == 22 || dstPort == 3389) && !isLoopbackIP(dstIP):
		finding = &detection.Finding{
			Severity:   "high",
			Confidence: 0.85,
			Title:      "AI agent connected to internal remote access service",
			Summary:    fmt.Sprintf("%s connected to internal host %s:%d (SSH/RDP)", aiType, dstIP, dstPort),
			Context: map[string]any{
				"ai_type":         aiType,
				"dst_ip":          dstIP,
				"dst_port":        dstPort,
				"pid":             evt.Process.PID,
				"comm":            evt.Process.Comm,
				"internal_threat":  "internal_remote_access",
				"signal_type":     "network_dest",
				"pattern":         fmt.Sprintf("%s:%d", dstIP, dstPort),
				"mitre_techniques": []string{"T1021"}, // Remote Services
			},
		}
	case internalCriticalPorts[dstPort] && !isLoopbackIP(dstIP):
		finding = &detection.Finding{
			Severity:   "critical",
			Confidence: 0.95,
			Title:      "AI agent connected to container runtime API",
			Summary:    fmt.Sprintf("%s connected to container API endpoint %s:%d", aiType, dstIP, dstPort),
			Context: map[string]any{
				"ai_type":         aiType,
				"dst_ip":          dstIP,
				"dst_port":        dstPort,
				"pid":             evt.Process.PID,
				"comm":            evt.Process.Comm,
				"internal_threat":  "container_api_access",
				"signal_type":     "network_dest",
				"pattern":         fmt.Sprintf("%s:%d", dstIP, dstPort),
				"mitre_techniques": []string{"T1610"}, // Deploy Container
			},
		}
	case internalInfraPorts[dstPort] && !isLoopbackIP(dstIP):
		finding = &detection.Finding{
			Severity:   "high",
			Confidence: 0.85,
			Title:      "AI agent connected to internal infrastructure service",
			Summary:    fmt.Sprintf("%s connected to infrastructure endpoint %s:%d", aiType, dstIP, dstPort),
			Context: map[string]any{
				"ai_type":         aiType,
				"dst_ip":          dstIP,
				"dst_port":        dstPort,
				"pid":             evt.Process.PID,
				"comm":            evt.Process.Comm,
				"internal_threat":  "internal_infra_access",
				"signal_type":     "network_dest",
				"pattern":         fmt.Sprintf("%s:%d", dstIP, dstPort),
				"mitre_techniques": []string{"T1046"}, // Network Service Discovery
			},
		}
	case internalDatabasePorts[dstPort] && !isLoopbackIP(dstIP):
		finding = &detection.Finding{
			Severity:   "medium",
			Confidence: 0.70,
			Title:      "AI agent connected to internal database service",
			Summary:    fmt.Sprintf("%s connected to internal database endpoint %s:%d", aiType, dstIP, dstPort),
			Context: map[string]any{
				"ai_type":         aiType,
				"dst_ip":          dstIP,
				"dst_port":        dstPort,
				"pid":             evt.Process.PID,
				"comm":            evt.Process.Comm,
				"internal_threat":  "internal_database_access",
				"signal_type":     "network_dest",
				"pattern":         fmt.Sprintf("%s:%d", dstIP, dstPort),
				"mitre_techniques": []string{"T1021"}, // Remote Services
			},
		}
	default:
		return nil
	}

	if evt.Process.SessionID != "" {
		finding.Context["session_id"] = evt.Process.SessionID
	}
	return finding
}

func isLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.IsLoopback()
}

// privateNetworks are pre-parsed RFC1918 CIDR ranges, allocated once at init.
var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNetworks = append(privateNetworks, network)
	}
}

// isPrivateIP checks if an IP is in RFC1918 private ranges, localhost, or link-local.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// isGenericPTR returns true if the domain looks like a generic reverse-DNS PTR record
// rather than a meaningful service domain. Examples:
//   - "137.66.149.34.bc.googleusercontent.com"
//   - "ec2-54-12-34-56.compute-1.amazonaws.com"
//   - "34-148-12-56.static.example.net"
func isGenericPTR(domain string) bool {
	genericSuffixes := []string{
		".bc.googleusercontent.com",
		".compute-1.amazonaws.com",
		".compute.amazonaws.com",
		".us-east-1.compute.internal",
		".us-west-2.compute.internal",
		".static.example.net",
		".in-addr.arpa",
	}
	for _, suffix := range genericSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}
