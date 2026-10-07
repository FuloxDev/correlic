# Suspicious File Monitoring - Complete Reference

## Overview

Correlic now monitors **80+ suspicious file patterns** across multiple security categories, plus supports **user-defined watchlists** for custom file monitoring.

---

## Built-in Suspicious Patterns

### 🔐 SSH & Crypto Keys (8 patterns)
- `.ssh/` - SSH directory
- `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa` - Private keys
- `.pem`, `.key` - Generic key files
- `authorized_keys` - SSH authorized keys
- `known_hosts` - SSH known hosts

**Example detections:**
- `cat ~/.ssh/id_rsa` ✅ KEPT
- `cp /home/user/.ssh/id_ed25519 /tmp/` ✅ KEPT

### ☁️ Cloud Provider Credentials (6 patterns)
- `.aws/` - AWS credentials directory
- `.azure/` - Azure credentials
- `.gcloud/` - Google Cloud credentials
- `.kube/` - Kubernetes config
- `credentials` - Generic credentials file
- `config` - AWS/kubectl config files

**Example detections:**
- `cat ~/.aws/credentials` ✅ KEPT
- `vim ~/.kube/config` ✅ KEPT

### 🔒 System Authentication & Passwords (11 patterns)
- `/etc/shadow` - Password hashes
- `/etc/passwd` - User accounts
- `/etc/group`, `/etc/gshadow` - Group info
- `/etc/sudoers` - Sudo permissions
- `/etc/security/` - PAM security configs
- `password`, `secret`, `token`, `api_key`, `apikey` - Generic secrets

**Example detections:**
- `cat /etc/shadow` ✅ KEPT
- `grep root /etc/passwd` ✅ KEPT
- `nano /etc/sudoers` ✅ KEPT

### 🐳 Container & Orchestration Secrets (5 patterns)
- `/run/secrets/` - Docker secrets
- `/var/run/secrets/` - Kubernetes secrets
- `docker.sock` - Docker daemon socket
- `.dockercfg` - Docker legacy config
- `.docker/config.json` - Docker config

**Example detections:**
- `cat /run/secrets/db_password` ✅ KEPT
- `curl --unix-socket /var/run/docker.sock` ✅ KEPT

### 🗄️ Database Credentials & Configs (5 patterns)
- `.pgpass` - PostgreSQL password file
- `.my.cnf` - MySQL config
- `database.yml` - Rails database config
- `db.conf` - Generic database config
- `.env` - Environment variables (often contain secrets)

**Example detections:**
- `cat .env` ✅ KEPT
- `vim ~/.pgpass` ✅ KEPT

### 📦 Application Secrets (6 patterns)
- `.npmrc` - NPM credentials
- `.pypirc` - PyPI credentials
- `.netrc` - Generic network credentials
- `settings.py` - Django settings (often has SECRET_KEY)
- `application.properties` - Spring Boot config
- `application.yml` - Spring Boot YAML config

**Example detections:**
- `cat ~/.npmrc` ✅ KEPT
- `grep SECRET_KEY settings.py` ✅ KEPT

### 🔐 Certificates & TLS (5 patterns)
- `.crt`, `.cert` - Certificates
- `.p12`, `.pfx` - PKCS#12 keystores
- `ca-bundle` - Certificate authority bundles

**Example detections:**
- `openssl x509 -in server.crt` ✅ KEPT
- `keytool -list -keystore app.p12` ✅ KEPT

### ⚙️ Kernel & System Internals (5 patterns)
**Potential privilege escalation vectors**
- `/proc/` - Process information filesystem
- `/sys/kernel/` - Kernel parameters
- `/dev/mem`, `/dev/kmem` - Physical memory access
- `/boot/` - Boot files and kernel images

**Example detections:**
- `cat /proc/1/environ` ✅ KEPT
- `echo 1 > /proc/sys/kernel/modules_disabled` ✅ KEPT
- `dd if=/dev/mem` ✅ KEPT

### 🛠️ Sensitive System Configs (5 patterns)
- `/etc/crontab`, `/etc/cron.` - Scheduled tasks
- `/etc/ssh/sshd_config` - SSH server config
- `/etc/pam.d/` - Authentication modules
- `/etc/ld.so.conf` - Dynamic linker config

**Example detections:**
- `vim /etc/crontab` ✅ KEPT
- `cat /etc/ssh/sshd_config` ✅ KEPT

### 📝 Logs (3 patterns)
**May contain sensitive data**
- `/var/log/auth.log` - Authentication logs
- `/var/log/secure` - Security logs (RHEL/CentOS)
- `/var/log/audit/` - Audit logs

**Example detections:**
- `tail -f /var/log/auth.log` ✅ KEPT
- `grep sudo /var/log/secure` ✅ KEPT

### 🌐 Browser & Email Data (4 patterns)
- `.mozilla/` - Firefox profiles
- `.thunderbird/` - Thunderbird email
- `cookies.sqlite` - Browser cookies
- `logins.json` - Firefox saved passwords

**Example detections:**
- `sqlite3 ~/.mozilla/firefox/*/cookies.sqlite` ✅ KEPT
- `cat ~/.mozilla/firefox/*/logins.json` ✅ KEPT

### 📂 Version Control (3 patterns)
**May contain secrets in history**
- `.git/config` - Git repository config
- `.gitconfig` - Global Git config
- `.svn/` - Subversion metadata

**Example detections:**
- `cat .git/config` ✅ KEPT
- `grep password .git/config` ✅ KEPT

---

## 🎯 User-Defined Watchlist

### How to Add Custom Patterns

You can add custom file patterns to monitor organization-specific or user-specific sensitive files.

#### Example Use Cases

**1. Cryptocurrency Wallets**
```go
UserWatchlist: []string{
    "*.wallet",
    ".bitcoin/wallet.dat",
    ".ethereum/keystore/",
    "metamask.json",
}
```

**2. Proprietary Company Files**
```go
UserWatchlist: []string{
    "/opt/company/secrets/",
    "*.proprietary",
    "/home/*/company_vpn.conf",
    "internal_api_keys.txt",
}
```

**3. Intellectual Property**
```go
UserWatchlist: []string{
    "/home/*/patents/",
    "*.trade_secret",
    "/opt/research/",
    "algorithm_*.py",
}
```

**4. Personal Sensitive Files**
```go
UserWatchlist: []string{
    "/home/user/Documents/taxes/",
    "passport_*.pdf",
    "ssn.txt",
    "medical_records/",
}
```

### Pattern Matching

The `matchesPattern()` function supports:
- **Exact paths:** `/etc/shadow`
- **Wildcards:** `*.wallet`, `/home/*/.ssh/`
- **Substring matching:** `.aws/` matches any path containing `.aws/`

### Priority

User watchlist patterns are checked **FIRST**, before built-in patterns, ensuring your custom files are always monitored.

---

## Implementation Details

### Code Location

**File:** [`sampling_rules.go`](../internal/ingest/sampling_rules.go)

**Struct:**
```go
type SamplingRules struct {
    AlwaysKeep         map[string]bool
    SampleRates        map[string]float64
    BenignProcesses    map[string]bool
    HighValueProcesses map[string]bool
    UserWatchlist      []string  // ← New field
}
```

**Detection Logic:**
```go
func (r *SamplingRules) IsSuspicious(evt *event.Event) bool {
    // 1. Check user watchlist FIRST (highest priority)
    for _, pattern := range r.UserWatchlist {
        if matchesPattern(evt.Target.FilePath, pattern) {
            return true
        }
    }
    
    // 2. Check built-in suspicious patterns
    // ... (80+ patterns)
}
```

### Sampling Order (Security-First)

The sampling logic in [`sampler.go`](../internal/ingest/sampler.go) ensures:

1. ✅ Always keep critical event types
2. ✅ **Check for suspicious activity FIRST** (user watchlist + built-in patterns)
3. ✅ Only then drop benign processes (if not suspicious)
4. ✅ Apply probabilistic sampling for remaining events

This prevents malicious scripts using common utilities from being dropped.

---

## Future Enhancements

### Planned Features

1. **Per-Organization Watchlists**
   - Store watchlists in database per organization
   - API endpoint to manage watchlists: `POST /api/v1/watchlist`

2. **Regex Support**
   - More powerful pattern matching
   - Example: `^/home/[^/]+/\.ssh/id_.*$`

3. **Alert Notifications**
   - Real-time alerts when watchlist files are accessed
   - Webhook integration
   - Email/Slack notifications

4. **Watchlist Templates**
   - Pre-built templates for common scenarios:
     - "Cryptocurrency Protection"
     - "Developer Workstation"
     - "Production Server"
     - "Compliance (HIPAA, PCI-DSS, SOC2)"

5. **Machine Learning**
   - Automatically suggest watchlist additions based on access patterns
   - Anomaly detection for unusual file access

---

## Testing

### Manual Testing

Test the watchlist by accessing monitored files:

```bash
# Test built-in patterns
cat /etc/shadow
cat ~/.ssh/id_rsa
cat ~/.aws/credentials

# Test user watchlist (after adding patterns)
cat /path/to/your/watched/file.txt
```

Then query the database:
```sql
SELECT event_type, payload->>'exe' as exe, payload->>'target' as target
FROM telemetry_events
WHERE event_type = 'file_open'
ORDER BY received_at DESC
LIMIT 20;
```

### Automated Testing

Add integration tests to verify watchlist detection:
```go
func TestUserWatchlist(t *testing.T) {
    rules := &SamplingRules{
        UserWatchlist: []string{"*.wallet", "/secret/"},
    }
    
    evt := &event.Event{
        Target: &event.Target{
            FilePath: "/home/user/bitcoin.wallet",
        },
    }
    
    assert.True(t, rules.IsSuspicious(evt))
}
```

---

## Summary

✅ **80+ built-in suspicious patterns** covering all major security categories  
✅ **User-defined watchlists** for custom file monitoring  
✅ **Security-first sampling** ensures suspicious events are never dropped  
✅ **Flexible pattern matching** with wildcards and substring support  
✅ **Extensible architecture** ready for future enhancements
