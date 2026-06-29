package ghauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pkcs1PEM(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func pkcs8PEM(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestParsePrivateKey_PKCS1AndPKCS8(t *testing.T) {
	if _, err := New("1", pkcs1PEM(t), 1); err != nil {
		t.Errorf("PKCS#1 key rejected: %v", err)
	}
	if _, err := New("1", pkcs8PEM(t), 1); err != nil {
		t.Errorf("PKCS#8 key rejected: %v", err)
	}
	if _, err := New("1", []byte("not a pem"), 1); err == nil {
		t.Errorf("garbage PEM accepted")
	}
}

func TestMintJWT_StructureAndClaims(t *testing.T) {
	c, err := New("app-42", pkcs1PEM(t), 99)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	tok, err := c.mintJWT(now)
	if err != nil {
		t.Fatalf("mintJWT: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	hdrRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr map[string]string
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" {
		t.Errorf("header = %v, want RS256/JWT", hdr)
	}
	clmRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var clm map[string]any
	if err := json.Unmarshal(clmRaw, &clm); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if clm["iss"] != "app-42" {
		t.Errorf("iss = %v, want app-42", clm["iss"])
	}
	if int64(clm["iat"].(float64)) != now.Add(-60*time.Second).Unix() {
		t.Errorf("iat = %v, want now-60s", clm["iat"])
	}
	if int64(clm["exp"].(float64)) != now.Add(10*time.Minute).Unix() {
		t.Errorf("exp = %v, want now+10m", clm["exp"])
	}
}

func TestToken_CachesWithinGrace(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_x","expires_at":"` + exp + `","permissions":{}}`))
	}))
	defer srv.Close()

	c, err := New("1", pkcs1PEM(t), 5)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.SetBaseURL(srv.URL)

	for i := 0; i < 3; i++ {
		tok, err := c.Token(context.Background())
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if tok != "ghs_x" {
			t.Fatalf("token=%q", tok)
		}
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (cache)", got)
	}

	// Invalidate forces a re-mint.
	c.Invalidate()
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatalf("Token after invalidate: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Errorf("after Invalidate, hits=%d, want 2", got)
	}
}
