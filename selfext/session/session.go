// Package session is the runtime SEAM that supplies inference credentials to
// mallcop's self-extension generative lanes (the K7 opencode author engine and
// the K8 add-only proposer) and, on the donut rail ONLY, the Forge BILLING
// preamble around each run.
//
// # Two rails, one safety surface
//
// A Session hides exactly ONE axis of variation: where inference is billed.
//
//   - donut.DonutSession (the COMMERCIAL rail, in internal/donut — NOT this
//     package) implements Session for the Forge donut rail. Authorize consults
//     the donut spend cap and mints a capped, lane-scoped, revocable Forge
//     subkey; Credentials hands back the Forge base URL + that subkey; Record
//     measures the real Forge usage delta and folds it into the spend ledger;
//     Close revokes the subkey and drains the pool. It reproduces the Forge
//     Authorize→Mint→GetUsage/Record→Revoke lifecycle the proposer/engine ran
//     inline before. It lives OUTSIDE this package precisely because it reaches
//     internal/forge + internal/selfext/subkey, which this package must not.
//
//   - BYOISession is the Bring-Your-Own-Inference rail for OSS users, and lives
//     HERE. It points at the user's OWN endpoint + key: Authorize is a no-op (NO
//     cap check, NO mint), Credentials returns (userURL, userKey), Record is $0
//     (NEVER a ledger decrement), Close is a no-op. It STRUCTURALLY holds no
//     Gate, Minter, or Forge handle, so "BYOI makes zero Forge billing calls" is
//     a property of the type, not of caller discipline.
//
// Everything OUTSIDE this seam — the anti-thrash reject set, the strict
// add-only parse, the trusted-signal prompt, the worktree jail, the human
// review of authored CODE, provenance, and transcript/key redaction — is
// identical on both rails. This package is the single place a reviewer confirms
// that BYOI drops ONLY billing and keeps every safety rail.
//
// # Import boundary
//
// session is Forge-free and subkey-free: it holds ONLY the abstract Session +
// SpendController seam and the BYOK BYOISession, so the whole self-extension
// engine graph (engine, proposer, router) that imports it stays clear of
// internal/forge and internal/selfext/subkey. engine and proposer import
// session (engine aliases SpendController to session.SpendController). session
// must NOT import engine, proposer, or the commercial donut package — that would
// cycle and would drag Forge back in.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Session is the per-run credential + billing seam. One Session instance backs
// one serialized generative loop; DonutSession keeps per-run state (the minted
// lease, the usage-window start) in fields that are reset each Close, so a
// single instance can be reused across a serial batch of runs.
//
// The call order a caller MUST follow mirrors the old inline lifecycle exactly:
//
//	Authorize(estUSD)              // donut: spend gate + mint subkey; BYOI: no-op
//	defer Close()                  // donut: revoke subkey + drain pool; BYOI: no-op
//	baseURL, key := Credentials()  // donut: (forgeURL, subkey); BYOI: (userURL, userKey)
//	   ... ONE inference call ...
//	cost := Record(success, estUSD)// donut: usage delta + ledger; BYOI: $0
type Session interface {
	// Authorize reserves budget for one run. On the donut rail it consults the
	// spend cap and, on success, mints the capped lane-scoped subkey; a benign
	// cap refusal is returned as a *RefusalError (the run spent nothing), while a
	// mint/resolver failure is returned as an ordinary (infrastructure) error.
	// On the BYOI rail it always succeeds.
	Authorize(ctx context.Context, estUSD float64) error
	// Credentials returns the inference (baseURL, key) for the ONE call and marks
	// the start of the usage-measurement window. Donut returns the Forge URL and
	// the minted subkey; BYOI returns the user's URL and key.
	Credentials(ctx context.Context) (baseURL, key string, err error)
	// Record measures and folds the run's spend into the ledger and returns the
	// measured cost. Donut sums the Forge usage delta since Credentials and calls
	// Gate.Record; BYOI records nothing and returns 0.
	Record(ctx context.Context, success bool, estUSD float64) (costUSD float64, err error)
	// Close tears the run down unconditionally. Donut revokes the subkey and
	// drains the pool; BYOI is a no-op. Safe to defer immediately after a
	// successful Authorize.
	Close() error
}

// SpendController is the spend-cap surface the donut rail needs. *spendcap.SpendGate
// satisfies it; tests inject a spy. It lives here (not in engine) so the donut
// session, the engine, and the proposer all name ONE definition —
// engine.SpendController is a type alias to this.
type SpendController interface {
	Authorize(ctx context.Context, class string, estUSD float64) error
	Record(class string, costUSD float64, success bool) error
	CapUSD() float64
}

// RefusalError marks a BENIGN spend-gate refusal: the run spent nothing and is a
// normal terminal state (Outcome{Refused}), NOT an infrastructure failure. The
// donut session wraps a gate denial in this type so callers can distinguish it
// from a mint/resolver error (which must surface as a hard error).
type RefusalError struct{ Err error }

func (e *RefusalError) Error() string {
	if e.Err == nil {
		return "spend refused"
	}
	return e.Err.Error()
}

func (e *RefusalError) Unwrap() error { return e.Err }

// AsRefusal reports whether err is (or wraps) a *RefusalError.
func AsRefusal(err error) (*RefusalError, bool) {
	var r *RefusalError
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

// keyFingerprint is a non-secret SHA-256 hash prefix of a credential, safe to
// log. It mirrors subkey.Lease.hashPrefix so a BYOI banner can identify the key
// in use without ever emitting the raw secret.
func keyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:12]
}
