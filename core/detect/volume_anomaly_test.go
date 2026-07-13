package detect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// volEvent builds an event whose payload carries the given metadata map under the
// nested "metadata" key — the corpus / eval-seeder on-disk shape payloadMeta
// reads. A nil meta yields an event with no magnitude field (weight 1).
func volEvent(id, source, evType, actor string, meta map[string]any) event.Event {
	payload := map[string]any{"action": "act", "target": "tgt"}
	if meta != nil {
		payload["metadata"] = meta
	}
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 8, 0, 0, 0, time.UTC),
		Payload:   raw,
	}
}

func volBaseline(freq map[string]int) *baseline.Baseline {
	return &baseline.Baseline{FrequencyTables: freq}
}

// TestVolumeAnomaly_MagnitudeFieldDrivesVolume is the field/unit contract fix
// (mallcoppro-3c9): the volume lives in a per-event magnitude field, and the
// detector must measure the SUMMED magnitude (not the count of event records)
// against the baseline. Eight storage_access records carrying blobs_accessed
// summing to 500 against a baseline of 10 is a 50x spike that MUST fire, even
// though only 8 records were emitted (8 < 3x10 would never fire on record count).
func TestVolumeAnomaly_MagnitudeFieldDrivesVolume(t *testing.T) {
	evs := []event.Event{
		volEvent("e1", "azure", "storage_access", "ci-bot", map[string]any{"blobs_accessed": 200}),
		volEvent("e2", "azure", "storage_access", "ci-bot", map[string]any{"blobs_accessed": 200}),
		volEvent("e3", "azure", "storage_access", "ci-bot", map[string]any{"blobs_accessed": 100}),
	}
	bl := volBaseline(map[string]int{"azure:storage_access:ci-bot": 10})

	got := volumeAnomalyEvaluateAll(evs, bl)
	if len(got) != 1 {
		t.Fatalf("expected 1 volume-anomaly finding, got %d: %+v", len(got), got)
	}
	if got[0].Type != "volume-anomaly" || got[0].Actor != "ci-bot" {
		t.Fatalf("finding shape wrong: %+v", got[0])
	}
	var ev map[string]any
	if err := json.Unmarshal(got[0].Evidence, &ev); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if ev["current_volume"] != float64(500) {
		t.Errorf("current_volume = %v, want 500 (summed magnitude, not 3 records)", ev["current_volume"])
	}
	if ev["event_records"] != float64(3) {
		t.Errorf("event_records = %v, want 3", ev["event_records"])
	}
}

// TestVolumeAnomaly_RecordCountFallbackUnchanged proves the legacy behavior is
// intact: events WITHOUT a magnitude field each weigh 1, so a spike measured in
// event records still fires exactly as before.
func TestVolumeAnomaly_RecordCountFallbackUnchanged(t *testing.T) {
	var evs []event.Event
	for i := 0; i < 40; i++ {
		evs = append(evs, volEvent("e", "azure", "login", "svc", nil))
	}
	bl := volBaseline(map[string]int{"azure:login:svc": 10})

	got := volumeAnomalyEvaluateAll(evs, bl)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding on a 40-vs-10 record spike, got %d", len(got))
	}
}

// TestVolumeAnomaly_AbsoluteFloorTinyBaseline proves the absolute-floor rule: a
// genuinely large burst (1200 operations) against a tiny baseline (2) fires, even
// though the baseline is below volumeMinBaselineCount — the tiny-baseline exfil
// case (CO-02). A SMALL burst against the same tiny baseline stays silent (the
// floor is what separates them, not a per-scenario rule).
func TestVolumeAnomaly_AbsoluteFloorTinyBaseline(t *testing.T) {
	big := []event.Event{volEvent("e1", "azure", "bulk_read", "deploy-svc", map[string]any{"operation_count": 1200})}
	bl := volBaseline(map[string]int{"azure:bulk_read:deploy-svc": 2})
	if got := volumeAnomalyEvaluateAll(big, bl); len(got) != 1 {
		t.Fatalf("expected 1 finding for a 1200-op burst vs baseline 2, got %d", len(got))
	}

	// Below the absolute floor AND below the min-baseline count: skipped.
	small := []event.Event{volEvent("e1", "azure", "bulk_read", "deploy-svc", map[string]any{"operation_count": 34})}
	if got := volumeAnomalyEvaluateAll(small, bl); len(got) != 0 {
		t.Fatalf("expected NO finding for a 34-op burst vs baseline 2 (below the absolute floor), got %d: %+v", len(got), got)
	}
}

// TestVolumeAnomaly_UnknownEventTypeSkipped proves an event type with no per-actor
// baseline (a brand-new behavior) never fires volume-anomaly — that is new-actor's
// job. Even a large magnitude against a zero baseline stays silent.
func TestVolumeAnomaly_UnknownEventTypeSkipped(t *testing.T) {
	evs := []event.Event{volEvent("e1", "azure", "bulk_read", "ext-user", map[string]any{"operation_count": 500})}
	bl := volBaseline(map[string]int{"azure:login:other": 100}) // no key for this group
	if got := volumeAnomalyEvaluateAll(evs, bl); len(got) != 0 {
		t.Fatalf("expected NO finding on a zero-baseline event type, got %d: %+v", len(got), got)
	}
}

// TestVolumeAnomaly_BenignBurstStaysSilent proves the false-positive guard: a
// handful of records with NO magnitude field against a healthy baseline is within
// normal variation and must not fire (the benign VA-01/02/05 twins' shape).
func TestVolumeAnomaly_BenignBurstStaysSilent(t *testing.T) {
	evs := []event.Event{
		volEvent("e1", "azure", "container_deploy", "deploy-svc", nil),
		volEvent("e2", "azure", "container_deploy", "deploy-svc", nil),
		volEvent("e3", "azure", "container_deploy", "deploy-svc", nil),
	}
	bl := volBaseline(map[string]int{"azure:container_deploy:deploy-svc": 156})
	if got := volumeAnomalyEvaluateAll(evs, bl); len(got) != 0 {
		t.Fatalf("expected NO finding on a benign 3-vs-156 burst, got %d: %+v", len(got), got)
	}
}
