package sieg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// enrollHarness wires up a CA, server cert, and a serverState bound to a
// real TLS httptest server with the /v1/enroll handler mounted. Tests
// can hit it from a real net/http client to exercise the full path.
type enrollHarness struct {
	dir       string
	cfgPath   string
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPemPath string
	psk       string
	server    *httptest.Server
	state     *serverState
}

func newEnrollHarness(t *testing.T) *enrollHarness {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := newSerial()
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "TestCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	caKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), caPemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), caKeyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// Generate a 32-byte PSK matching the production format.
	rawPSK := make([]byte, enrollPSKBytes)
	_, _ = rand.Read(rawPSK)
	psk := enrollPSKPrefix + hex.EncodeToString(rawPSK)

	cfgPath := filepath.Join(dir, "config.json")
	// Minimal config so addAgentToAllowlist round-trips cleanly.
	if err := os.WriteFile(cfgPath, []byte(`{"mode":"server","server":{"agent_allowlist":[]}}`), 0o640); err != nil {
		t.Fatal(err)
	}

	st := &serverState{
		base:              dir,
		group:             newStorageGroup(dir),
		allowlist:         map[string]struct{}{},
		fails:             map[string]*authFailRate{},
		enrollPSK:         psk,
		certsDir:          dir,
		configPath:        cfgPath,
		enrollClientYears: 5,
		enrollLimiter:     newRateLimiter(100, 100),
		reauthSeconds:     60,
		storages:          map[string]*Storage{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", st.handleEnroll)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		// Release Storage file handles so Windows TempDir cleanup works.
		st.closeAll()
	})

	return &enrollHarness{
		dir:       dir,
		cfgPath:   cfgPath,
		caCert:    caCert,
		caKey:     caKey,
		caPemPath: filepath.Join(dir, "ca.pem"),
		psk:       psk,
		server:    srv,
		state:     st,
	}
}

func makeCSR(t *testing.T, cn string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), priv
}

func postEnroll(t *testing.T, h *enrollHarness, body EnrollRequest) (*http.Response, []byte) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/v1/enroll", strings.NewReader(string(buf)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	respBody := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			respBody = append(respBody, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return resp, respBody
}

func TestPSKRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// Override defaultStateDir's path for this test by writing directly.
	psk := enrollPSKPrefix + hex.EncodeToString(make([]byte, enrollPSKBytes))
	if _, err := pskRawBytes(psk); err != nil {
		t.Errorf("zero PSK should still hex-decode: %v", err)
	}
	if _, err := pskRawBytes("garbage"); err == nil {
		t.Error("missing prefix should fail")
	}
	if _, err := pskRawBytes(enrollPSKPrefix + "zzznothex"); err == nil {
		t.Error("non-hex should fail")
	}
}

func TestEnroll_HappyPath(t *testing.T) {
	h := newEnrollHarness(t)
	csrPem, priv := makeCSR(t, "agent-1")
	resp, body := postEnroll(t, h, EnrollRequest{
		PSK: h.psk, AgentID: "agent-1", CSRPem: csrPem,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var er EnrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if er.CertPem == "" || er.CAPem == "" || er.Hmac == "" {
		t.Fatal("response missing fields")
	}
	if er.ReauthSeconds != 60 {
		t.Errorf("reauth_seconds=%d, want 60", er.ReauthSeconds)
	}
	if !er.NewlyAdded {
		t.Error("first enrollment should be NewlyAdded=true")
	}
	// Verify HMAC via the canonical helper (avoids drift between
	// test and prod when the HMAC inputs evolve).
	rawPSK, _ := pskRawBytes(h.psk)
	want := computeEnrollHMAC(rawPSK, er.CertPem, er.CAPem, er.ReauthSeconds, er.RealmName, er.RealmPeers)
	if er.Hmac != want {
		t.Errorf("hmac mismatch")
	}
	// Verify the issued cert chains and matches our key.
	if err := verifyEnrolledCert(er.CertPem, er.CAPem, "agent-1", &priv.PublicKey); err != nil {
		t.Errorf("verify: %v", err)
	}
	// Verify the agent_id was added to the allowlist on disk.
	cfg := loadConfig(h.cfgPath)
	found := false
	for _, id := range cfg.Server.AgentAllowlist {
		if id == "agent-1" {
			found = true
		}
	}
	if !found {
		t.Error("agent-1 not in persisted allowlist")
	}
	// Verify in-memory state too.
	h.state.allowlistMu.RLock()
	_, ok := h.state.allowlist["agent-1"]
	h.state.allowlistMu.RUnlock()
	if !ok {
		t.Error("agent-1 not in in-memory allowlist")
	}
}

func TestEnroll_BadPSK(t *testing.T) {
	h := newEnrollHarness(t)
	csrPem, _ := makeCSR(t, "agent-1")
	resp, _ := postEnroll(t, h, EnrollRequest{
		PSK:     enrollPSKPrefix + hex.EncodeToString(make([]byte, enrollPSKBytes)),
		AgentID: "agent-1",
		CSRPem:  csrPem,
	})
	if resp.StatusCode != 401 {
		t.Errorf("status=%d, want 401", resp.StatusCode)
	}
}

func TestEnroll_MalformedPSK(t *testing.T) {
	h := newEnrollHarness(t)
	csrPem, _ := makeCSR(t, "agent-1")
	resp, _ := postEnroll(t, h, EnrollRequest{
		PSK: "not-a-real-psk", AgentID: "agent-1", CSRPem: csrPem,
	})
	if resp.StatusCode != 401 {
		t.Errorf("status=%d, want 401", resp.StatusCode)
	}
}

func TestEnroll_CNMismatch(t *testing.T) {
	h := newEnrollHarness(t)
	// CSR's CN is "different", but we claim agent_id="agent-1".
	csrPem, _ := makeCSR(t, "different")
	resp, body := postEnroll(t, h, EnrollRequest{
		PSK: h.psk, AgentID: "agent-1", CSRPem: csrPem,
	})
	if resp.StatusCode != 400 {
		t.Errorf("status=%d body=%s, want 400", resp.StatusCode, body)
	}
}

func TestEnroll_InvalidAgentID(t *testing.T) {
	h := newEnrollHarness(t)
	csrPem, _ := makeCSR(t, "../escape")
	resp, _ := postEnroll(t, h, EnrollRequest{
		PSK: h.psk, AgentID: "../escape", CSRPem: csrPem,
	})
	if resp.StatusCode != 400 {
		t.Errorf("status=%d, want 400 for path-traversal agent_id", resp.StatusCode)
	}
}

func TestEnroll_BadCSR(t *testing.T) {
	h := newEnrollHarness(t)
	resp, _ := postEnroll(t, h, EnrollRequest{
		PSK: h.psk, AgentID: "agent-1", CSRPem: "not pem",
	})
	if resp.StatusCode != 400 {
		t.Errorf("status=%d, want 400", resp.StatusCode)
	}
}

func TestEnroll_Idempotent(t *testing.T) {
	h := newEnrollHarness(t)
	for i := 0; i < 2; i++ {
		csrPem, _ := makeCSR(t, "agent-1")
		resp, body := postEnroll(t, h, EnrollRequest{
			PSK: h.psk, AgentID: "agent-1", CSRPem: csrPem,
		})
		if resp.StatusCode != 200 {
			t.Fatalf("iter %d: status=%d body=%s", i, resp.StatusCode, body)
		}
		var er EnrollResponse
		_ = json.Unmarshal(body, &er)
		if i == 0 && !er.NewlyAdded {
			t.Error("first enrollment: NewlyAdded should be true")
		}
		if i == 1 && er.NewlyAdded {
			t.Error("second enrollment: NewlyAdded should be false")
		}
	}
}

func TestEnroll_RateLimited(t *testing.T) {
	h := newEnrollHarness(t)
	h.state.enrollLimiter = newRateLimiter(1, 2) // burst=2, then throttled
	csrPem, _ := makeCSR(t, "agent-1")
	got429 := false
	for i := 0; i < 5; i++ {
		resp, _ := postEnroll(t, h, EnrollRequest{
			PSK: h.psk, AgentID: "agent-1", CSRPem: csrPem,
		})
		if resp.StatusCode == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("expected at least one 429 from a flood of 5 requests with burst=2")
	}
}

func TestComputeEnrollHMAC_Deterministic(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	a := computeEnrollHMAC(psk, "cert", "ca", 60, "default", nil)
	b := computeEnrollHMAC(psk, "cert", "ca", 60, "default", nil)
	if a != b {
		t.Error("HMAC not deterministic")
	}
	// Different realm name → different HMAC.
	if a == computeEnrollHMAC(psk, "cert", "ca", 60, "other", nil) {
		t.Error("HMAC should differ when realm name differs")
	}
	// Different peer list → different HMAC.
	if a == computeEnrollHMAC(psk, "cert", "ca", 60, "default", []string{"https://x"}) {
		t.Error("HMAC should differ when realm peers differ")
	}
	c := computeEnrollHMAC(psk, "cert", "ca", 30, "default", nil)
	if a == c {
		t.Error("HMAC should differ when reauth_seconds differs")
	}
}

func TestEnroll_ServerHandlesConcurrency(t *testing.T) {
	// Make sure concurrent enrollments don't race the in-memory allowlist
	// or the on-disk config write. This won't catch every race but the
	// race detector will scream if there's a hot one.
	h := newEnrollHarness(t)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "agent-" + string(rune('a'+i))
			csrPem, _ := makeCSR(t, id)
			resp, _ := postEnroll(t, h, EnrollRequest{
				PSK: h.psk, AgentID: id, CSRPem: csrPem,
			})
			if resp.StatusCode != 200 {
				t.Errorf("agent %s: status=%d", id, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	// All 5 should be in the allowlist.
	cfg := loadConfig(h.cfgPath)
	if len(cfg.Server.AgentAllowlist) != 5 {
		t.Errorf("allowlist size=%d after 5 concurrent enrollments, want 5: %v",
			len(cfg.Server.AgentAllowlist), cfg.Server.AgentAllowlist)
	}
}
