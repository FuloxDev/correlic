# Enrichment APIs

IP address enrichment for network event analysis — resolves IPs to domains, ASN info, and BGP prefixes.

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/enrich/ip` | Resolve single IP to domain + ASN + BGP prefix |
| POST | `/api/v1/enrich/ips` | Bulk resolve up to 50 IPs concurrently |

### POST /api/v1/enrich/ip

**Request:**
```json
{ "ip": "1.2.3.4" }
```

**Response:**
```json
{
  "ip": "1.2.3.4",
  "domain": "example.com",
  "source": "reverse_dns",
  "asn_name": "CLOUDFLARENET",
  "asn": "13335",
  "bgp_prefix": "1.2.3.0/24",
  "reverse_dns": "one.one.one.one"
}
```

**Source field values:**
- `"reverse_dns"` — domain from PTR record
- `"asn_inferred"` — domain inferred from ASN name (when PTR is generic)
- `""` — no domain could be determined

Generic PTR records (matching common ISP patterns) are filtered out and treated as empty.

### POST /api/v1/enrich/ips

**Request:**
```json
{ "ips": ["1.2.3.4", "5.6.7.8"] }
```

**Response:**
```json
{ "results": [/* array of ipResult objects */] }
```

- Max 50 IPs per request
- Deduplicated (duplicate IPs resolved once)
- All lookups run concurrently with cached results (800ms timeout)
- Invalid IPs silently skipped

## Network & Port Analysis Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/network/summary` | Network activity overview (connection counts, top destinations) |
| GET | `/network/domain` | DNS query statistics |
| GET | `/network/destination` | Connection target analysis |
| GET | `/ports/summary` | Open ports summary |
| GET | `/ports/service` | Service-level port info |

## Key Files

| File | Purpose |
|------|---------|
| `internal/api/enrich_handler.go` | `ResolveIP()`, `ResolveBulkIPs()` HTTP handlers |
| `internal/enrichment/netinfo.go` | `GlobalEnricher` — cached DNS/ASN/BGP lookups |
| `internal/api/network_handlers.go` | Network summary, domain, destination handlers |
| `internal/api/ports_summary.go` | Ports summary + service handlers |
