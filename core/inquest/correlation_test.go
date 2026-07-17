package inquest

import (
	"math/rand"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
)

// TestAssembleScanCorrelation_Positive proves a synthetic scan register with
// occurrences firing +120s±30s after each scan yields correlated:true and a
// median offset near 120s — the exact "hourly, ~2min after each scheduled
// scan" shape the forge-proxy motivating case needs.
func TestAssembleScanCorrelation_Positive(t *testing.T) {
	s := newTempStore(t)
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	var occ []time.Time
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 8; i++ {
		scanTime := base.Add(time.Duration(i) * time.Hour)
		if _, err := s.Append(store.KindScans, store.ScanRecord{StartedAt: scanTime, FinishedAt: scanTime}); err != nil {
			t.Fatalf("append scan record: %v", err)
		}
		jitter := time.Duration(rnd.Intn(61)-30) * time.Second // ±30s
		occ = append(occ, scanTime.Add(120*time.Second+jitter))
	}

	out := assembleScanCorrelation(s, occ, 10*time.Minute)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	if out.ScanCount != 8 {
		t.Errorf("ScanCount = %d, want 8", out.ScanCount)
	}
	if !out.Correlated {
		t.Errorf("Correlated = false, want true (out=%+v)", out)
	}
	if out.MedianOffsetSeconds < 60 || out.MedianOffsetSeconds > 180 {
		t.Errorf("MedianOffsetSeconds = %v, want ~120 (within [60,180])", out.MedianOffsetSeconds)
	}
	if out.MatchedFraction < 0.7 {
		t.Errorf("MatchedFraction = %v, want >= 0.7", out.MatchedFraction)
	}
}

// TestAssembleScanCorrelation_NegativeRandomOffsets proves occurrences at
// RANDOM (uncorrelated) offsets from the scan schedule yield correlated:false.
func TestAssembleScanCorrelation_NegativeRandomOffsets(t *testing.T) {
	s := newTempStore(t)
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	var occ []time.Time
	rnd := rand.New(rand.NewSource(2))
	for i := 0; i < 8; i++ {
		scanTime := base.Add(time.Duration(i) * time.Hour)
		if _, err := s.Append(store.KindScans, store.ScanRecord{StartedAt: scanTime, FinishedAt: scanTime}); err != nil {
			t.Fatalf("append scan record: %v", err)
		}
		// Occurrence offset uniformly random over the WHOLE inter-scan
		// interval — no consistent post-scan cadence at all.
		randOffset := time.Duration(rnd.Intn(3600)) * time.Second
		occ = append(occ, scanTime.Add(randOffset))
	}

	out := assembleScanCorrelation(s, occ, 10*time.Minute)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	if out.Correlated {
		t.Errorf("Correlated = true, want false for random offsets (out=%+v)", out)
	}
}

// TestAssembleScanCorrelation_FewerThanFiveScans proves the scan_count>=5
// gate: even a PERFECT offset pattern with too few observed scans is not
// correlated.
func TestAssembleScanCorrelation_FewerThanFiveScans(t *testing.T) {
	s := newTempStore(t)
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	var occ []time.Time
	for i := 0; i < 3; i++ {
		scanTime := base.Add(time.Duration(i) * time.Hour)
		if _, err := s.Append(store.KindScans, store.ScanRecord{StartedAt: scanTime, FinishedAt: scanTime}); err != nil {
			t.Fatalf("append scan record: %v", err)
		}
		occ = append(occ, scanTime.Add(120*time.Second))
	}

	out := assembleScanCorrelation(s, occ, 10*time.Minute)
	if out.Correlated {
		t.Errorf("Correlated = true with only %d scans, want false (scan_count>=5 gate)", out.ScanCount)
	}
}

// TestAssembleScanCorrelation_NoScansOrOccurrences proves empty inputs
// degrade to a clean zero-value result, no error, no panic.
func TestAssembleScanCorrelation_NoScansOrOccurrences(t *testing.T) {
	s := newTempStore(t)
	out := assembleScanCorrelation(s, nil, 10*time.Minute)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	if out.ScanCount != 0 || out.Correlated {
		t.Errorf("expected zero-value result on empty store, got %+v", out)
	}
}

// TestLoadScanTimes_ClustersNearSimultaneousCommits proves loadScanTimes
// collapses commits within 10 minutes of each other into one anchor time —
// so one scan's several stream commits don't inflate scan_count.
func TestLoadScanTimes_ClustersNearSimultaneousCommits(t *testing.T) {
	s := newTempStore(t)
	// Two Appends to events.jsonl land as two commits, effectively
	// back-to-back (well within 10 minutes of each other in real time).
	if _, err := s.Append(store.KindEvents, map[string]any{"id": 1}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(store.KindEvents, map[string]any{"id": 2}); err != nil {
		t.Fatalf("append: %v", err)
	}
	times, err := loadScanTimes(s)
	if err != nil {
		t.Fatalf("loadScanTimes: %v", err)
	}
	if len(times) != 1 {
		t.Fatalf("loadScanTimes returned %d clustered times, want 1 (both commits land in the same second/cluster)", len(times))
	}
}

// TestClusterTimes proves clusterTimes collapses runs within window to their
// earliest member and starts a new cluster once the gap exceeds window.
func TestClusterTimes(t *testing.T) {
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	in := []time.Time{
		base, base.Add(2 * time.Minute), base.Add(9 * time.Minute), // all within 10min of base
		base.Add(25 * time.Minute), // > 10min from the 9-min mark's own anchor chain -> new cluster
	}
	out := clusterTimes(in, 10*time.Minute)
	if len(out) != 2 {
		t.Fatalf("clusterTimes returned %d clusters, want 2: %v", len(out), out)
	}
	if !out[0].Equal(base) {
		t.Errorf("first cluster anchor = %v, want %v", out[0], base)
	}
}
