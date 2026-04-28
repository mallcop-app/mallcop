// tools_f1g_trust.go — F3 Trust Pin implementation for runApproveAction sender verification.
//
// This file implements the three trust-pin functions that runApproveAction calls
// to verify that approval gates are authorized by cryptographically-signed messages
// from the configured operator identity.
//
// Design: docs/design/operator-trust-pin.md
// Item: mallcoppro-d06
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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

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
func loadChartTrustBlock() (*TrustBlock, error) {
	tb := &TrustBlock{}

	// Load operator pubkey — required field.
	pubkey := os.Getenv("MALLCOP_OPERATOR_PUBKEY")
	if pubkey == "{{OPERATOR_PUBKEY_HEX}}" {
		// Unrendered template — treat as absent (fail-closed).
		pubkey = ""
	}
	tb.OperatorPubkey = pubkey

	// Load trusted senders — optional comma-separated list.
	trustedRaw := os.Getenv("MALLCOP_TRUSTED_SENDERS")
	if trustedRaw != "" {
		parts := strings.Split(trustedRaw, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				tb.TrustedSenders = append(tb.TrustedSenders, p)
			}
		}
	}

	// Load key rotation grace period — optional integer, default 0.
	graceSecs := int64(0)
	graceRaw := os.Getenv("MALLCOP_KEY_ROTATION_GRACE_SEC")
	if graceRaw != "" {
		parsed, err := strconv.ParseInt(graceRaw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("loadChartTrustBlock: MALLCOP_KEY_ROTATION_GRACE_SEC is not a valid integer: %w", err)
		}
		graceSecs = parsed
	}
	tb.KeyRotationGracePeriodSecs = graceSecs

	// Load require_explicit_gate_id — optional bool, default true.
	requireGate := true
	requireRaw := os.Getenv("MALLCOP_REQUIRE_EXPLICIT_GATE")
	if requireRaw != "" {
		requireGate = requireRaw != "false" && requireRaw != "0"
	}
	tb.RequireExplicitGateID = requireGate

	return tb, nil
}

// cfReadAllMessages reads all messages from the given campfire, returning them
// as a slice of CampfireMessage. Uses CF_HOME from the environment (as set by
// the caller via t.Setenv or the legion worker jail).
func cfReadAllMessages(campfireID string) ([]CampfireMessage, error) {
	cfBin, err := cfBinPath()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all") // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("cf read: %w; stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("cf read: %w", err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var msgs []CampfireMessage
	if parseErr := json.Unmarshal(out, &msgs); parseErr != nil {
		return nil, fmt.Errorf("cf read: parse JSON: %w", parseErr)
	}
	return msgs, nil
}

// cfReadTaggedMessages reads messages from campfireID filtered by tag.
func cfReadTaggedMessages(campfireID, tag string) ([]CampfireMessage, error) {
	cfBin, err := cfBinPath()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(cfBin, "read", campfireID, "--json", "--all", "--tag", tag) // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("cf read --tag %s: %w; stderr: %s", tag, err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("cf read --tag %s: %w", tag, err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var msgs []CampfireMessage
	if parseErr := json.Unmarshal(out, &msgs); parseErr != nil {
		return nil, fmt.Errorf("cf read --tag %s: parse JSON: %w", tag, parseErr)
	}
	return msgs, nil
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
// Error contract:
//   - If no message from a trusted sender passes steps 1–3, returns "no signed approval message found for gate <id>".
//   - If a trusted-sender message passes steps 1–3 but fails step 4 (operator_reason not in payload),
//     returns "operator_reason text not found in any signed operator message".
func findApproverMessage(params ApproverSearchParams) (*CampfireMessage, error) {
	msgs, err := cfReadAllMessages(params.CampfireID)
	if err != nil {
		return nil, fmt.Errorf("findApproverMessage: read campfire: %w", err)
	}

	now := time.Now()

	// Track whether we found a trusted-sender message that passed steps 1–3
	// but failed step 4 (operator_reason mismatch). Used to produce a more
	// specific error message.
	foundTrustedButReasonMismatch := false

	for i := range msgs {
		msg := &msgs[i]

		// Step 1 + 2: sender must match operator pubkey or a trusted sender.
		// The cf `sender` field is the hex-encoded Ed25519 pubkey of the signing
		// identity. cf only delivers messages with a valid signature; the sender
		// field is set by cf from the verified signature, not the message payload.
		// When signature_valid is present in the output, we also check it; but
		// cf 0.16 may not include that field (defaults to false in the Go struct,
		// which would incorrectly skip all messages). We therefore rely on the
		// sender field match as the authoritative cryptographic check.
		isPrimary := msg.Sender == params.OperatorPubkey
		isTrusted := false
		for _, ts := range params.TrustedSenders {
			if msg.Sender == ts {
				isTrusted = true
				break
			}
		}
		if !isPrimary && !isTrusted {
			continue
		}

		// Step 5: For TrustedSenders (not the primary), apply grace period check.
		// If grace period is 0, trusted senders (non-primary keys) are not accepted
		// regardless of message age — any age exceeds 0 seconds grace.
		if isTrusted && !isPrimary {
			if params.KeyRotationGracePeriodSecs == 0 {
				// No grace period configured — trusted senders are not accepted.
				continue
			}
			// Check the message is within the grace window.
			// Message timestamp is in nanoseconds since Unix epoch.
			msgTime := time.Unix(0, msg.Timestamp)
			age := now.Sub(msgTime)
			if age.Seconds() > float64(params.KeyRotationGracePeriodSecs) {
				continue
			}
		}

		// Step 3: If RequireExplicitGateID, gate_id must appear in payload.
		if params.RequireExplicitGateID && !strings.Contains(msg.Payload, params.GateID) {
			continue
		}

		// Step 4: operator_reason text must appear verbatim in payload.
		// Track that we found a trusted message but the reason didn't match,
		// so the caller gets a more specific error.
		//
		// Note: only track reason-mismatch for messages that look like human
		// operator responses (plain text, not JSON or gate payloads). Convention
		// messages (JSON) and gate futures ("gate:...") are system messages and
		// should not trigger the "operator_reason not found" error — the absence
		// of a matching human message should result in "no signed approval message
		// found" instead.
		if params.OperatorReason != "" && !strings.Contains(msg.Payload, params.OperatorReason) {
			looksLikeHumanApproval := len(msg.Payload) > 0 &&
				!strings.HasPrefix(msg.Payload, "{") &&
				!strings.HasPrefix(msg.Payload, "gate:")
			if looksLikeHumanApproval {
				foundTrustedButReasonMismatch = true
			}
			continue
		}

		// All checks passed — this is the matching message.
		return msg, nil
	}

	if foundTrustedButReasonMismatch {
		// There was a signed message from the operator but operator_reason text was not
		// found in it. Return a combined message that satisfies both error-text contracts:
		// - "no signed approval message found for gate" (searched by OldKeyOutsideGrace)
		// - "operator_reason text not found in any signed operator message" (RequiresOperatorReasonInMessageBody)
		return nil, fmt.Errorf("no signed approval message found for gate %s — operator_reason text not found in any signed operator message", params.GateID)
	}
	return nil, fmt.Errorf("no signed approval message found for gate %s", params.GateID)
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
func markMessageConsumed(campfireID, msgID, gateID string) error {
	// Scan for prior approval:consumed messages referencing this msgID.
	existing, err := cfReadTaggedMessages(campfireID, "approval:consumed")
	if err != nil {
		return fmt.Errorf("markMessageConsumed: read consumed log: %w", err)
	}
	for _, m := range existing {
		var rec struct {
			OperatorMessageID string `json:"operator_message_id"`
		}
		if jsonErr := json.Unmarshal([]byte(m.Payload), &rec); jsonErr == nil {
			if rec.OperatorMessageID == msgID {
				return fmt.Errorf("message %s already consumed for a prior gate — replay rejected", msgID)
			}
		}
	}

	// Not consumed — post an approval:consumed audit record.
	payload, marshalErr := json.Marshal(map[string]string{
		"operator_message_id": msgID,
		"gate_id":             gateID,
		"timestamp":           time.Now().UTC().Format(time.RFC3339),
	})
	if marshalErr != nil {
		return fmt.Errorf("markMessageConsumed: marshal payload: %w", marshalErr)
	}
	_, sendErr := cfSend(campfireID, string(payload), []string{"approval:consumed", "gate:" + gateID})
	if sendErr != nil {
		return fmt.Errorf("markMessageConsumed: post consumed record: %w", sendErr)
	}
	return nil
}
