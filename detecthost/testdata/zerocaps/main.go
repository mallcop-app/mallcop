// Command zerocaps is a detecthost e2e test fixture (see
// detecthost_test.go's TestDetectZeroCapabilities): it is a real
// detect.Detector, run through the real host, whose ONLY job is to probe the
// capabilities available to it and report what it found. It proves the
// zero-WASI-capability claim empirically — from INSIDE the sandbox — rather
// than by only inspecting the host's ModuleConfig calls.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// zerocapsProbe reports whether the sandbox handed it a filesystem, an
// environment, or none of the above.
type zerocapsProbe struct{}

var _ detect.Detector = zerocapsProbe{}

func (zerocapsProbe) Name() string { return "zerocaps-probe" }

func (zerocapsProbe) Detect(_ []event.Event, _ *baseline.Baseline) []finding.Finding {
	_, openErr := os.Open("/etc/passwd")
	home, homeSet := os.LookupEnv("HOME")
	path, pathSet := os.LookupEnv("PATH")

	evidence, _ := json.Marshal(map[string]any{
		"open_etc_passwd_err": fmt.Sprint(openErr),
		"env_home_set":        homeSet,
		"env_home_value":      home,
		"env_path_set":        pathSet,
		"env_path_value":      path,
	})
	return []finding.Finding{{
		ID:       "zerocaps-probe",
		Source:   "detector:zerocaps-probe",
		Severity: "low",
		Type:     "zerocaps-probe",
		Reason:   "capability probe",
		Evidence: evidence,
	}}
}

func main() {
	os.Exit(detectorhost.Run(zerocapsProbe{}))
}
