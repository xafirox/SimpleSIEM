package sieg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mtlsHarness is a self-contained CA + server + client cert set used by
// the convert-agent connectivity tests. The server runs on a real port
// with mTLS so the production validateAgentReadyForConvert path exercises
// the same TLS code it does in the field.
type mtlsHarness struct {
	dir        string
	clientCert string
	clientKey  string
	caCertPath string
	server     *httptest.Server
	url        string
}

func newMTLSHarness(t *testing.T, agentID string, status int) *mtlsHarness {
	t.Helper()
	dir := t.TempDir()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := newSerial()
	caTmpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject:      pkix.Name{CommonName: "TestRootCA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPath := filepath.Join(dir, "ca.pem")
	if err := writePEM(caPath, "CERTIFICATE", caDER, false); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvSerial, _ := newSerial()
	srvTmpl := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clSerial, _ := newSerial()
	clTmpl := &x509.Certificate{
		SerialNumber: clSerial,
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clDER, _ := x509.CreateCertificate(rand.Reader, clTmpl, caCert, &clientKey.PublicKey, caKey)
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client.key")
	if err := writeKeyPair(clientCertPath, clientKeyPath, clDER, clientKey); err != nil {
		t.Fatalf("write client: %v", err)
	}

	srvTLSCert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvKey,
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if status >= 400 {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"received":0,"rejected":0}`))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &mtlsHarness{
		dir:        dir,
		clientCert: clientCertPath,
		clientKey:  clientKeyPath,
		caCertPath: caPath,
		server:     srv,
		url:        srv.URL,
	}
}

func TestValidateAgentReadyForConvert_EmptyServerURL(t *testing.T) {
	err := validateAgentReadyForConvert(AgentConfig{}, "host1")
	if err == nil || !strings.Contains(err.Error(), "agent.server_url") {
		t.Errorf("expected server_url error, got: %v", err)
	}
}

func TestValidateAgentReadyForConvert_MissingCertPaths(t *testing.T) {
	err := validateAgentReadyForConvert(AgentConfig{
		ServerURL: "https://nope:9443",
	}, "host1")
	if err == nil || !strings.Contains(err.Error(), "agent.client_cert") {
		t.Errorf("expected client_cert error, got: %v", err)
	}
}

func TestValidateAgentReadyForConvert_MissingCertFile(t *testing.T) {
	dir := t.TempDir()
	err := validateAgentReadyForConvert(AgentConfig{
		ServerURL:  "https://nope:9443",
		ClientCert: filepath.Join(dir, "missing.pem"),
		ClientKey:  filepath.Join(dir, "missing.key"),
		CACert:     filepath.Join(dir, "missing-ca.pem"),
	}, "host1")
	if err == nil || !strings.Contains(err.Error(), "missing at") {
		t.Errorf("expected missing-file error, got: %v", err)
	}
}

func TestValidateAgentReadyForConvert_ConnectionRefused(t *testing.T) {
	// Pick a port that's almost certainly closed. Using 1 is safer
	// than a random "high" number that might be taken by another process.
	h := newMTLSHarness(t, "host1", 200)
	err := validateAgentReadyForConvert(AgentConfig{
		ID:         "host1",
		ServerURL:  "https://127.0.0.1:1",
		ClientCert: h.clientCert,
		ClientKey:  h.clientKey,
		CACert:     h.caCertPath,
	}, "host1")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not accepting connections") &&
		!strings.Contains(msg, "could not reach") &&
		!strings.Contains(msg, "did not respond") {
		t.Errorf("error should describe connection failure, got: %q", msg)
	}
}

func TestValidateAgentReadyForConvert_HappyPath(t *testing.T) {
	h := newMTLSHarness(t, "host1", 200)
	if err := validateAgentReadyForConvert(AgentConfig{
		ID:         "host1",
		ServerURL:  h.url,
		ClientCert: h.clientCert,
		ClientKey:  h.clientKey,
		CACert:     h.caCertPath,
	}, "host1"); err != nil {
		t.Errorf("expected success against fully-configured mTLS server, got: %v", err)
	}
}

func TestValidateAgentReadyForConvert_AllowlistRejection(t *testing.T) {
	h := newMTLSHarness(t, "host1", http.StatusForbidden)
	err := validateAgentReadyForConvert(AgentConfig{
		ID:         "host1",
		ServerURL:  h.url,
		ClientCert: h.clientCert,
		ClientKey:  h.clientKey,
		CACert:     h.caCertPath,
	}, "host1")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	msg := err.Error()
	if !strings.Contains(msg, "agent_allowlist") || !strings.Contains(msg, "re-enroll") {
		t.Errorf("403 error should mention agent_allowlist + suggest re-enrollment, got: %q", msg)
	}
}

func TestValidateAgentReadyForConvert_WrongEndpoint(t *testing.T) {
	h := newMTLSHarness(t, "host1", http.StatusNotFound)
	err := validateAgentReadyForConvert(AgentConfig{
		ID:         "host1",
		ServerURL:  h.url,
		ClientCert: h.clientCert,
		ClientKey:  h.clientKey,
		CACert:     h.caCertPath,
	}, "host1")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "/v1/events") {
		t.Errorf("404 error should mention /v1/events, got: %q", err)
	}
}

func TestValidateAgentReadyForConvert_UntrustedCA(t *testing.T) {
	// Build TWO CAs. The agent trusts CA-A; the server presents a cert
	// signed by CA-B. The TLS handshake must fail.
	a := newMTLSHarness(t, "host1", 200)
	b := newMTLSHarness(t, "host1", 200)
	// Use server B's URL but agent A's CA bundle and client cert.
	err := validateAgentReadyForConvert(AgentConfig{
		ID:         "host1",
		ServerURL:  b.url,
		ClientCert: a.clientCert,
		ClientKey:  a.clientKey,
		CACert:     a.caCertPath, // mismatch — this CA didn't sign B's server cert
	}, "host1")
	if err == nil {
		t.Fatal("expected error for CA mismatch")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ca_cert") && !strings.Contains(msg, "trusted") && !strings.Contains(msg, "x509") {
		t.Errorf("CA-mismatch error should mention trust / ca_cert, got: %q", msg)
	}
	// Avoid unused warnings if both harnesses are needed only for cleanup.
	_ = os.Getenv
}
