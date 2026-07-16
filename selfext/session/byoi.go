package session

import (
	"context"
	"errors"
	"log/slog"
)

// BYOISession is the Bring-Your-Own-Inference rail: the OSS user runs the
// automated generative lanes against THEIR OWN endpoint + key, off the metered
// commercial rail entirely. Per an explicit, accepted-risk decision, BYOI has NO
// spend cap and NO minted run key — the user's own key is the user's own blast
// radius.
//
// The struct STRUCTURALLY holds no Gate, Minter, or billing handle, so
// "BYOI never touches the metered billing rails" is guaranteed by construction:
//   - Authorize is a no-op (no cap check, no mint) — it cannot refuse.
//   - Credentials returns the user's (URL, key) verbatim.
//   - Record is $0 and NEVER decrements any ledger; it only optionally emits a
//     non-secret banner (endpoint + key FINGERPRINT, never the raw key).
//   - Close is a no-op (nothing to revoke).
//
// Every safety rail OUTSIDE billing — anti-thrash, strict add-only parse, the
// trusted-signal prompt, the jail, human review of code, provenance, and the
// transcript/key redaction — runs identically to the metered rail.
type BYOISession struct {
	// BaseURL is the user's inference endpoint (e.g. their own gateway, an
	// Anthropic-compatible gateway, a local proxy). Not a secret.
	BaseURL string
	// Key is the user's inference API key. Held in memory only, flowed into the
	// inference client and (for the code lane) the sandbox provider config; NEVER
	// logged raw, never written to a bare env var or a committed file.
	Key string
	// Logger receives the non-secret BYOI banner. Nil → no banner.
	Logger *slog.Logger
}

var _ Session = (*BYOISession)(nil)

// Authorize is a no-op: BYOI has no spend cap and mints no run key. It always
// succeeds — a BYOI run is never Refused on cost grounds.
func (s *BYOISession) Authorize(_ context.Context, _ float64) error { return nil }

// Credentials returns the user's endpoint and key. Both must be present; an
// empty URL or key is a hard configuration error (the CLI XOR guard should have
// caught it first, but this is the byte-level backstop).
func (s *BYOISession) Credentials(_ context.Context) (string, string, error) {
	if s.BaseURL == "" || s.Key == "" {
		return "", "", errors.New("session: BYOI requires both an inference URL and a key")
	}
	return s.BaseURL, s.Key, nil
}

// Record spends nothing and decrements no ledger. It optionally logs a
// non-secret banner recording the endpoint and a key FINGERPRINT (never the raw
// key) so an operator can audit that a run was billed to the user's endpoint.
// It ALWAYS returns 0 cost.
func (s *BYOISession) Record(_ context.Context, success bool, _ float64) (float64, error) {
	if s.Logger != nil {
		s.Logger.Info("BYOI: no cap — inference billed to the user's own endpoint",
			"endpoint", s.BaseURL,
			"key_fingerprint", keyFingerprint(s.Key),
			"success", success,
		)
	}
	return 0, nil
}

// Close is a no-op: there is no run key to revoke and no pool to drain.
func (s *BYOISession) Close() error { return nil }
