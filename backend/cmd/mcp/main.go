// Command correlic-mcp is the Correlic Model Context Protocol server: it
// exposes findings, incidents, agent activity and telemetry to MCP clients
// (Claude Code, Claude Desktop, Cursor, ...) over stdio, backed by the
// Correlic REST API.
//
// Configuration is by environment:
//
//	CORRELIC_API_URL                  API plane base URL (default https://localhost:8080)
//	CORRELIC_API_KEY                  dashboard API key; decides what the tools can see
//	CORRELIC_TLS_CA_FILE              CA that signed the API certificate (bootstrap's ca.crt)
//	CORRELIC_TLS_CLIENT_CERT_FILE     client certificate for mTLS (bootstrap's client.crt)
//	CORRELIC_TLS_CLIENT_KEY_FILE      its key (client.key)
//
// Writes (correlic.finding.resolve) are off unless --allow-writes is given
// (or CORRELIC_MCP_ALLOW_WRITES=true). See backend/docs/MCP_SERVER.md.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/correlic/correlic-backend/internal/mcp"
)

const serverName = "correlic-mcp"

// version is set by the release builds (-X main.version=...).
var version = "dev"

func main() {
	allowWrites := flag.Bool("allow-writes", envBool("CORRELIC_MCP_ALLOW_WRITES"), "enable the write tools (correlic.finding.resolve)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(serverName + " " + version)
		return
	}
	// stdout is the MCP transport; everything else goes to stderr.
	log.SetOutput(os.Stderr)

	baseURL := strings.TrimSpace(os.Getenv("CORRELIC_API_URL"))
	if baseURL == "" {
		baseURL = "https://localhost:8080"
	}
	apiKey := strings.TrimSpace(os.Getenv("CORRELIC_API_KEY"))
	if apiKey == "" {
		log.Printf("WARN: CORRELIC_API_KEY is not set; every tool call will be rejected by the API")
	}
	client, err := mcp.NewClient(baseURL, apiKey, mcp.TLSOptions{
		CAFile:         os.Getenv("CORRELIC_TLS_CA_FILE"),
		ClientCertFile: os.Getenv("CORRELIC_TLS_CLIENT_CERT_FILE"),
		ClientKeyFile:  os.Getenv("CORRELIC_TLS_CLIENT_KEY_FILE"),
	})
	if err != nil {
		log.Fatalf("correlic-mcp: %v", err)
	}

	tools := mcp.NewToolSet(client, *allowWrites)
	if *allowWrites {
		log.Printf("correlic-mcp %s: writes enabled (correlic.finding.resolve)", version)
	}
	srv := mcp.NewServer(mcp.ServerInfo{Name: serverName, Version: version}, tools.Tools(), tools.Call)
	srv.SetInstructions(mcp.Instructions(*allowWrites))
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
