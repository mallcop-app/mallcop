package session

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// ---- BYOISession ------------------------------------------------------------

// TestBYOISessionNeverBills proves the BYOI rail drops ONLY billing: Authorize
// never refuses (no cap), Credentials returns the user's own endpoint+key,
// Record is $0 and touches no ledger, Close is a no-op. The struct holds no
// Gate/Minter/Forge handle, so "no Forge billing call" is structural.
func TestBYOISessionNeverBills(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	s := &BYOISession{BaseURL: "https://user.example/v1", Key: "sk-ant-USERKEY-12345", Logger: log}
	ctx := context.Background()

	if err := s.Authorize(ctx, 999999.0); err != nil {
		t.Errorf("BYOI Authorize should always succeed (no cap), got %v", err)
	}
	baseURL, key, err := s.Credentials(ctx)
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if baseURL != "https://user.example/v1" || key != "sk-ant-USERKEY-12345" {
		t.Errorf("Credentials = (%q,%q), want the user's own URL+key", baseURL, key)
	}
	cost, err := s.Record(ctx, true, 5.0)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if cost != 0 {
		t.Errorf("BYOI Record cost = %v, want 0 (never a ledger decrement)", cost)
	}
	if err := s.Close(); err != nil {
		t.Errorf("BYOI Close should be a no-op, got %v", err)
	}
	// The banner must never contain the raw key — only its fingerprint.
	if strings.Contains(buf.String(), "sk-ant-USERKEY-12345") {
		t.Errorf("BYOI banner leaked the raw key: %q", buf.String())
	}
	if !strings.Contains(buf.String(), keyFingerprint("sk-ant-USERKEY-12345")) {
		t.Errorf("BYOI banner missing the key fingerprint: %q", buf.String())
	}
}

// TestBYOISessionSatisfiesSessionInterface pins the BYOK seam: a *BYOISession is
// usable ANYWHERE a Session is expected AND, driven strictly through the
// interface handle, it authorizes without a cap, records $0, and never touches a
// ledger (no Gate/Minter/Forge is even held). This is the property the whole
// forge-free engine graph relies on.
func TestBYOISessionSatisfiesSessionInterface(t *testing.T) {
	// Compile-time: BYOISession IS a Session.
	var sess Session = &BYOISession{BaseURL: "https://user.example/v1", Key: "sk-user-abc"}
	ctx := context.Background()

	// Authorize never refuses on cost grounds (no cap surface exists).
	if err := sess.Authorize(ctx, 1e9); err != nil {
		t.Fatalf("Authorize through Session: %v", err)
	}
	if _, ok := AsRefusal(nil); ok {
		t.Fatalf("AsRefusal(nil) should be false")
	}
	url, key, err := sess.Credentials(ctx)
	if err != nil {
		t.Fatalf("Credentials through Session: %v", err)
	}
	if url != "https://user.example/v1" || key != "sk-user-abc" {
		t.Errorf("Credentials = (%q,%q), want the user's own URL+key", url, key)
	}
	// Record through the interface returns exactly $0 — no ledger decrement.
	cost, err := sess.Record(ctx, true, 42.0)
	if err != nil {
		t.Fatalf("Record through Session: %v", err)
	}
	if cost != 0 {
		t.Errorf("BYOI Record via Session = %v, want 0 (no ledger)", cost)
	}
	if err := sess.Close(); err != nil {
		t.Errorf("Close through Session should be a no-op, got %v", err)
	}
}

// TestBYOISessionCredentialsGuard: an empty URL or key is a hard error.
func TestBYOISessionCredentialsGuard(t *testing.T) {
	for _, tc := range []struct{ url, key string }{{"", "k"}, {"u", ""}, {"", ""}} {
		s := &BYOISession{BaseURL: tc.url, Key: tc.key}
		if _, _, err := s.Credentials(context.Background()); err == nil {
			t.Errorf("Credentials(url=%q,key=%q) should error", tc.url, tc.key)
		}
	}
}

// ---- helpers ----------------------------------------------------------------

func TestRefusalErrorUnwrap(t *testing.T) {
	inner := errors.New("cap exceeded")
	r := &RefusalError{Err: inner}
	if r.Error() != "cap exceeded" {
		t.Errorf("Error() = %q, want the inner message", r.Error())
	}
	if !errors.Is(r, inner) {
		t.Errorf("RefusalError should unwrap to the inner error")
	}
	got, ok := AsRefusal(errors.Join(errors.New("x"), r))
	if !ok || got != r {
		t.Errorf("AsRefusal should find a wrapped RefusalError")
	}
	if _, ok := AsRefusal(errors.New("plain")); ok {
		t.Errorf("AsRefusal should be false for a plain error")
	}
}

func TestKeyFingerprint(t *testing.T) {
	if keyFingerprint("") != "" {
		t.Errorf("empty key should fingerprint to empty")
	}
	fp := keyFingerprint("sk-ant-secret")
	if len(fp) != 12 {
		t.Errorf("fingerprint len = %d, want 12", len(fp))
	}
	if strings.Contains("sk-ant-secret", fp) {
		t.Errorf("fingerprint must not be a substring of the key")
	}
	if fp != keyFingerprint("sk-ant-secret") {
		t.Errorf("fingerprint must be deterministic")
	}
}
