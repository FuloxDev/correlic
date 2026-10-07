package ai_pack

import (
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// fallbackDNSCategories maps domain suffixes to categories for when the agent
// does not populate evt.Context["category"]. This ensures known-bad TLDs are
// still detected even if the agent's categorization logic has a bug.
var fallbackDNSCategories = []struct {
	suffix   string
	category string
}{
	// Tor / anonymization — critical
	{".onion", "tor"},
	{".i2p", "tor"},
	// Tunneling services — high (expose internal services to internet)
	{"ngrok.io", "tunneling"},
	{"ngrok-free.app", "tunneling"},
	{"trycloudflare.com", "tunneling"},
	{"bore.pub", "tunneling"},
	{"loca.lt", "tunneling"},
	{"serveo.net", "tunneling"},
	// Paste services — medium
	{"pastebin.com", "paste_service"},
	{"paste.ee", "paste_service"},
	{"ghostbin.com", "paste_service"},
	{"dpaste.org", "paste_service"},
	{"hastebin.com", "paste_service"},
	{"rentry.co", "paste_service"},
	// File sharing — medium
	{"transfer.sh", "file_share"},
	{"file.io", "file_share"},
	{"0x0.st", "file_share"},
	{"anonfiles.com", "file_share"},
	{"mega.nz", "file_share"},
	{"mediafire.com", "file_share"},
	// Suspicious TLDs — high (frequently used in malware/phishing)
	{".bit", "suspicious_tld"},
	{".bazar", "suspicious_tld"},
	{".coin", "suspicious_tld"},
	{".tk", "suspicious_tld"},
	{".ml", "suspicious_tld"},
	{".ga", "suspicious_tld"},
	{".cf", "suspicious_tld"},
	{".top", "suspicious_tld"},
}

// AISuspiciousDNS detects when an AI agent process queries suspicious DNS names.
// The agent pre-categorizes domains via categorizeDNS() and populates
// evt.Context["category"]. This rule triggers on known-bad categories only.
type AISuspiciousDNS struct{}

func (d *AISuspiciousDNS) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.suspicious_dns",
		Pack:            "ai",
		Name:            "AI Suspicious DNS Query",
		Severity:        "high",
		Description:     "AI agent process queried a suspicious domain (Tor, paste service, file share, or suspicious TLD)",
		Tags:            []string{"ai", "dns", "exfiltration", "c2"},
		MITRETechniques: []string{"T1568", "T1071.004"},
	}
}

func (d *AISuspiciousDNS) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"net_dns"},
		WindowSecs: 0,
	}
}

func (d *AISuspiciousDNS) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Target == nil || evt.Target.Domain == "" {
		return nil
	}
	if evt.Process == nil {
		return nil
	}

	domain := evt.Target.Domain

	// Only fire for AI agent processes.
	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	// Skip domains that are explicitly allowlisted.
	if ctx.SafeDomainChecker != nil && ctx.SafeDomainChecker.IsSafe(domain) {
		return nil
	}

	// Read the category stamped by the agent, normalizing to lowercase.
	category, _ := evt.Context["category"].(string)
	category = strings.ToLower(category)

	// Fallback: if agent didn't categorize, check known-bad suffixes ourselves.
	if category == "" {
		lowerDomain := strings.ToLower(domain)
		for _, fb := range fallbackDNSCategories {
			if strings.HasSuffix(lowerDomain, fb.suffix) {
				category = fb.category
				break
			}
		}
	}

	// DNS tunneling detection: data encoded in subdomain labels.
	// Signal: subdomain labels longer than 30 chars (normal labels are ≤20).
	if category == "" && isDNSTunneling(domain) {
		category = "dns_tunneling"
	}

	var severity string
	var confidence float64

	switch category {
	case "tor":
		severity = "critical"
		confidence = 0.95
	case "dns_tunneling":
		severity = "high"
		confidence = 0.80
	case "tunneling":
		severity = "high"
		confidence = 0.85
	case "suspicious_tld":
		severity = "high"
		confidence = 0.85
	case "paste_service":
		severity = "medium"
		confidence = 0.75
	case "file_share":
		severity = "medium"
		confidence = 0.70
	default:
		// No category from agent — skip.
		return nil
	}

	// Per-finding MITRE technique based on DNS category.
	var mitreTechniques []string
	switch category {
	case "tor":
		mitreTechniques = []string{"T1090.003"} // Multi-hop Proxy
	case "dns_tunneling":
		mitreTechniques = []string{"T1071.004"} // Application Layer Protocol: DNS
	case "tunneling":
		mitreTechniques = []string{"T1572"} // Protocol Tunneling
	case "suspicious_tld":
		mitreTechniques = []string{"T1568"} // Dynamic Resolution
	case "paste_service":
		mitreTechniques = []string{"T1567.003"} // Exfiltration to Text Storage Sites
	case "file_share":
		mitreTechniques = []string{"T1567.002"} // Exfiltration to Cloud Storage
	}

	fctx := map[string]any{
		"dns_query":   domain,
		"category":    category,
		"ai_type":     aiType,
		"host_id":     ctx.HostID,
		"pid":         evt.Process.PID,
		"signal_type": "dns_domain",
		"pattern":     domain,
	}
	if len(mitreTechniques) > 0 {
		fctx["mitre_techniques"] = mitreTechniques
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}

	return []detection.Finding{{
		Title:      "Suspicious DNS query by AI agent: " + domain,
		Summary:    "AI agent process queried a " + category + " domain (" + domain + "), which may indicate C2 communication or data exfiltration",
		Severity:   severity,
		Confidence: confidence,
		Context:    fctx,
	}}
}

// isDNSTunneling checks if a domain name looks like DNS tunneling —
// data encoded in long subdomain labels. Normal subdomain labels are
// typically under 20 characters. Tunneling encodes data in base64/hex
// resulting in labels of 30+ characters.
func isDNSTunneling(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 3 {
		return false // needs at least subdomain.domain.tld
	}

	// Check subdomain labels (everything except the last 2 labels = domain.tld)
	subLabels := labels[:len(labels)-2]
	longLabels := 0
	totalSubLen := 0

	for _, label := range subLabels {
		totalSubLen += len(label)
		if len(label) > 30 {
			longLabels++
		}
	}

	// Trigger on: any single label > 30 chars, or total subdomain > 50 chars
	return longLabels > 0 || totalSubLen > 50
}
