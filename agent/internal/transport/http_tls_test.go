package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedCertPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "correlic-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Create cert: %v", err)
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem.Encode cert: %v", err)
	}

	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("Create key: %v", err)
	}
	defer kf.Close()
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("pem.Encode key: %v", err)
	}

	return certFile, keyFile
}

func TestTLSConfigFromFiles_NoConfig(t *testing.T) {
	cfg, err := tlsConfigFromFiles("", "", "")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil cfg")
	}
}

func TestTLSConfigFromFiles_ErrOnPartialClientCert(t *testing.T) {
	_, err := tlsConfigFromFiles("", "/tmp/client.crt", "")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestTLSConfigFromFiles_LoadsClientCertPair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCertPair(t, dir)

	cfg, err := tlsConfigFromFiles("", certFile, keyFile)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if cfg == nil {
		t.Fatalf("expected cfg")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 client certificate, got %d", len(cfg.Certificates))
	}
}

