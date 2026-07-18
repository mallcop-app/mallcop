package cases

import "encoding/json"

// entityKeys is the fallback chain ExtractEntity tries, in order: the first
// key present with a non-empty string value wins. "grantee" is
// core/detect/new_external_access.go's external-principal key; "target" and
// "member" are the same detector's companion evidence fields (aligns with
// connectors v0.9.0's promoted target/member evidence shape). No detector
// emits a top-level "member" evidence key today (it currently appears only as
// a metaStr alias search term) — the fallback is forward-looking, kept
// exactly as specified, not dead code.
var entityKeys = []string{"grantee", "target", "member"}

// ExtractEntity pulls the primary-entity value out of a Finding's Evidence
// blob for case clustering, per entityKeys' fallback order. Fail-open,
// mirroring pkg/finding.ExtractEvidenceEventIDs's style: unparseable or empty
// evidence, or no matching key, yields "" — never an error. "" is itself a
// valid (if coarse) cluster entity: findings whose evidence carries none of
// these keys still cluster on (type, actor, "").
func ExtractEntity(evidence json.RawMessage) string {
	if len(evidence) == 0 {
		return ""
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(evidence, &parsed); err != nil {
		return ""
	}
	for _, k := range entityKeys {
		raw, ok := parsed[k]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s != "" {
			return s
		}
	}
	return ""
}
