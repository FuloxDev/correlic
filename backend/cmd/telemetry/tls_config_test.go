package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCACert(t *testing.T, dir string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "correlic-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	p := filepath.Join(dir, "ca.pem")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	return p
}

func TestTLSConfigFromEnv_DisabledWhenUnset(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	t.Setenv("MTLS_CA_FILE", "")

	enabled, _, _, cfg, err := tlsConfigFromEnv()
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if enabled {
		t.Fatalf("expected disabled")
	}
	if cfg != nil {
		t.Fatalf("expected nil cfg when disabled")
	}
}

func TestTLSConfigFromEnv_ErrWhenPartialTLSVars(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/tmp/cert.pem")
	t.Setenv("TLS_KEY_FILE", "")
	t.Setenv("MTLS_CA_FILE", "")

	_, _, _, _, err := tlsConfigFromEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestTLSConfigFromEnv_RequiresClientCertWhenCAProvided(t *testing.T) {
	dir := t.TempDir()
	ca := writeTestCACert(t, dir)

	t.Setenv("TLS_CERT_FILE", filepath.Join(dir, "server.pem"))
	t.Setenv("TLS_KEY_FILE", filepath.Join(dir, "server.key"))
	t.Setenv("MTLS_CA_FILE", ca)

	enabled, _, _, cfg, err := tlsConfigFromEnv()
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled")
	}
	if cfg == nil || cfg.ClientAuth == 0 {
		t.Fatalf("expected tls config with ClientAuth set")
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("expected VerifyClientCertIfGiven, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatalf("expected ClientCAs pool")
	}
}
