// tools_f1g_trust.go — F3 Trust Pin stubs for runApproveAction sender verification.
//
// This file contains the TrustBlock struct and the three functions that
// mallcoppro-d06 must implement. All function bodies return a sentinel error so
// that the TDD test file (tools_f1g_trust_test.go) compiles and fails
// deterministically on this branch.
//
// DO NOT add production logic here. mallcoppro-d06 fills these bodies.
//
// Environment variables consumed (all injected by the legion worker jail):
//
//	MALLCOP_OPERATOR_PUBKEY        — hex Ed25519 pubkey from chart [trust].operator_pubkey
//	MALLCOP_TRUSTED_SENDERS        — comma-separated list of additional trusted pubkeys
//	MALLCOP_KEY_ROTATION_GRACE_SEC — seconds both old and new key are valid (default 0)
//	MALLCOP_REQUIRE_EXPLICIT_GATE  — "true" or "false" (default "true")
//	MALLCOP_OPERATOR_CAMPFIRE_ID   — campfire on which operator approval messages appear
//	CF_HOME                        — campfire home directory (standard cf env)
package main

import (
	"errors"
)

// errNotImplemented is the sentinel error returned by all stub functions in this
// file. Tests assert on this string. The impl (mallcoppro-d06) replaces all
// occurrences of this error with real logic.
var errNotImplemented = errors.New("not implemented — mallcoppro-d06")

// TrustBlock holds the trust configuration loaded from the chart's [trust] block.
// Fields correspond 1:1 to the TOML keys defined in docs/design/operator-trust-pin.md §2.
//
// Sources: environment variables injected at legion startup:
//
//	MALLCOP_OPERATOR_PUBKEY        → OperatorPubkey
//	MALLCOP_TRUSTED_SENDERS        → TrustedSenders (comma-separated)
//	MALLCOP_KEY_ROTATION_GRACE_SEC → KeyRotationGracePeriodSecs
//	MALLCOP_REQUIRE_EXPLICIT_GATE  → RequireExplicitGateID
type TrustBlock struct {
	// OperatorPubkey is the hex-encoded Ed25519 public key of the trusted human
	// operator. Required. If empty, the zero-value placeholder
	// "{{OPERATOR_PUBKEY_HEX}}", or missing entirely, runApproveAction MUST fail
	// closed with "trust block missing or operator_pubkey unconfigured — fail closed".
	OperatorPubkey string

	// TrustedSenders is an optional list of additional operator pubkeys (e.g.,
	// for multi-operator or key-rotation setups). Approval from ANY listed key is
	// sufficient. During key rotation, the old key goes here while OperatorPubkey
	// holds the new key and KeyRotationGracePeriodSecs > 0.
	TrustedSenders []string

	// KeyRotationGracePeriodSecs is the number of seconds during which both the
	// old key (listed in TrustedSenders) and the new OperatorPubkey are
	// simultaneously valid. Zero means no grace — only OperatorPubkey is trusted.
	KeyRotationGracePeriodSecs int64

	// RequireExplicitGateID, when true, requires the gate_id string to appear
	// verbatim in the operator's approval message body. Defaults to true.
	// Disabling this weakens replay protection and should only be done
	// intentionally.
	RequireExplicitGateID bool
}

// ApproverSearchParams is the input to findApproverMessage. It bundles all
// parameters needed to scan the operator campfire for a valid approval message.
type ApproverSearchParams struct {
	// CampfireID is the operator campfire to scan.
	CampfireID string
	// OperatorPubkey is the primary trusted sender pubkey (64-char hex).
	OperatorPubkey string
	// TrustedSenders is the list of additional trusted pubkeys (may be empty).
	TrustedSenders []string
	// GateID is the gate that must be mentioned in the message body (when
	// RequireExplicitGateID is true).
	GateID string
	// RequireExplicitGateID mirrors the TrustBlock field.
	RequireExplicitGateID bool
	// OperatorReason is the verbatim text that must appear in the signed message
	// body (defeat synthesized-text bypass, design §4 step 3).
	OperatorReason string
	// KeyRotationGracePeriodSecs — messages from TrustedSenders older than this
	// many seconds are rejected even if the sender is in TrustedSenders.
	KeyRotationGracePeriodSecs int64
}

// CampfireMessage is the minimal representation of a campfire message returned
// by "cf read --json". The impl reads the real JSON; the struct is defined here
// so tests can reason about the fields.
type CampfireMessage struct {
	ID             string `json:"id"`
	Sender         string `json:"sender"`
	Payload        string `json:"payload"`
	SignatureValid bool   `json:"signature_valid"`
	// Timestamp is nanoseconds since Unix epoch (as returned by cf read --json).
	Timestamp int64 `json:"timestamp"`
}

// loadChartTrustBlock reads the chart [trust] configuration from environment
// variables injected by the legion runtime. It returns a non-nil *TrustBlock on
// success, or an error if the env is missing or malformed.
//
// Env vars consumed:
//
//	MALLCOP_OPERATOR_PUBKEY
//	MALLCOP_TRUSTED_SENDERS        (comma-separated, may be empty)
//	MALLCOP_KEY_ROTATION_GRACE_SEC (integer seconds, default 0)
//	MALLCOP_REQUIRE_EXPLICIT_GATE  ("true"/"false", default "true")
//
// Fail-closed invariant: if OperatorPubkey is absent, empty, or the unrendered
// template literal "{{OPERATOR_PUBKEY_HEX}}", the returned TrustBlock has
// OperatorPubkey == "" so that runApproveAction can detect and reject.
//
// mallcoppro-d06: implement this function.
func loadChartTrustBlock() (*TrustBlock, error) {
	return nil, errNotImplemented
}

// findApproverMessage scans the operator campfire for a message that:
//  1. Was sent by params.OperatorPubkey or one of params.TrustedSenders.
//  2. Has signature_valid == true (cf's own Ed25519 verification).
//  3. Contains params.GateID verbatim in the payload (when RequireExplicitGateID).
//  4. Contains params.OperatorReason verbatim in the payload.
//  5. Is not older than KeyRotationGracePeriodSecs relative to now (for
//     TrustedSenders keys only — the primary OperatorPubkey has no age limit).
//
// Returns the matching CampfireMessage or an error describing why no valid
// message was found.
//
// mallcoppro-d06: implement this function.
func findApproverMessage(params ApproverSearchParams) (*CampfireMessage, error) {
	return nil, errNotImplemented
}

// markMessageConsumed checks whether msgID has already been consumed for a prior
// gate (replay protection), and if not, posts an "approval:consumed" message to
// the operator campfire recording the consumption.
//
// The campfire-backed consumed-message log is the source of truth (design §7).
// A process crash between markMessageConsumed and cfFulfills leaves no consumed
// record, so a retry by the operator works correctly.
//
// Returns an error containing "already consumed" if the message has been used
// for a prior gate.
//
// mallcoppro-d06: implement this function.
func markMessageConsumed(campfireID, msgID, gateID string) error {
	return errNotImplemented
}
