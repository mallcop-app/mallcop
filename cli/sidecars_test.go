package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// sidecarsTestRepoRoot walks up from the test binary's working directory
// (cli/, under `go test`) to the go.mod marker. Mirrors core/lint's coreRoot
// helper and detecthost_test.go's repoRoot.
func sidecarsTestRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

func sidecarsTestGoBin(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	const fallback = "/usr/local/go/bin/go"
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	t.Fatal("go toolchain not found on $PATH or at /usr/local/go/bin/go")
	return ""
}

// buildExampleSidecarWasm compiles examples/sidecar-detector to a wasip1 wasm
// module and writes it into dir under a NAME UNIQUE to this test invocation
// (a nanosecond suffix) — core/detect.Register panics on a duplicate detector
// Name, and detecthost.Detector.Name() is the file's basename stem, so a
// fixed filename risks colliding with a previous run of this same test
// function within one `go test` process (e.g. -count=2). Returns the .wasm
// path.
func buildExampleSidecarWasm(t *testing.T, dir string) string {
	t.Helper()
	root := sidecarsTestRepoRoot(t)

	name := "sidecar-example-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".wasm"
	out := filepath.Join(dir, name)

	cmd := exec.Command(sidecarsTestGoBin(t), "build", "-o", out, "./examples/sidecar-detector")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build examples/sidecar-detector (GOOS=wasip1 GOARCH=wasm): %v\n%s", err, outBytes)
	}
	return out
}

// TestRunDetect_PicksUpSidecarFromConfiguredDir is the mallcoppro-f70
// end-to-end integration proof: a real .wasm sidecar detector, discovered from
// a mallcop.yaml's detectors.sidecars.dir, registered through the real
// detecthost + wazero host, and its finding appears in `mallcop detect`
// output exactly like a built-in detector's would.
func TestRunDetect_PicksUpSidecarFromConfiguredDir(t *testing.T) {
	deploymentDir := t.TempDir()
	sidecarsDir := filepath.Join(deploymentDir, "bin")
	if err := os.MkdirAll(sidecarsDir, 0o755); err != nil {
		t.Fatalf("mkdir sidecars dir: %v", err)
	}
	wasmPath := buildExampleSidecarWasm(t, sidecarsDir)
	sidecarName := strings.TrimSuffix(filepath.Base(wasmPath), filepath.Ext(wasmPath))

	cfgPath := filepath.Join(deploymentDir, "mallcop.yaml")
	cfgYAML := fmt.Sprintf("version: 1\ndetectors:\n  sidecars:\n    dir: %s\n", sidecarsDir)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write mallcop.yaml: %v", err)
	}
	t.Setenv(config.EnvConfigPath, cfgPath)

	// sidecar-example fires on any event whose Type is
	// exampledetector.EventType ("sidecar-example-trigger").
	stdin := `{"id":"s1","source":"probe","type":"sidecar-example-trigger","actor":"quinn"}` + "\n"

	out, err := withStdio(t, stdin, func() error { return runDetect(nil) })
	if !isFindingsError(err) {
		t.Fatalf("expected the findings sentinel (a finding was detected), got %v; stdout=%s", err, out)
	}

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var f finding.Finding
		if uerr := json.Unmarshal([]byte(line), &f); uerr != nil {
			t.Fatalf("output line is not a valid Finding: %v\nline: %s", uerr, line)
		}
		if f.Source == "detector:sidecar-example" && f.Actor == "quinn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the sidecar (%s) finding for actor 'quinn' in detect output; got:\n%s", sidecarName, out)
	}
}

// TestResolveSidecarsDir_DefaultAndOverride locks in the resolution rules
// resolveSidecarsDir implements: config-relative when a config file was
// discovered, verbatim when absolute, and the ./detectors/bin default when
// unset.
func TestResolveSidecarsDir_DefaultAndOverride(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.Config
		cfgPath string
		want    string
	}{
		{
			name:    "no config discovered uses bare default",
			cfg:     config.Defaults(),
			cfgPath: "",
			want:    "./detectors/bin",
		},
		{
			name:    "config-relative dir resolves against config's directory",
			cfg:     config.Config{Detectors: config.Detectors{Sidecars: config.Sidecars{Dir: "sidecars"}}},
			cfgPath: filepath.Join("deploy", "mallcop.yaml"),
			want:    filepath.Join("deploy", "sidecars"),
		},
		{
			name:    "absolute dir used verbatim",
			cfg:     config.Config{Detectors: config.Detectors{Sidecars: config.Sidecars{Dir: "/opt/sidecars"}}},
			cfgPath: filepath.Join("deploy", "mallcop.yaml"),
			want:    "/opt/sidecars",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveSidecarsDir(tc.cfg, tc.cfgPath)
			if got != tc.want {
				t.Fatalf("resolveSidecarsDir = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLoadSidecarDetectors_AbsentDirIsNoop proves the OOTB default: a
// sidecars.dir that does not exist on disk yields zero sidecars and no error.
func TestLoadSidecarDetectors_AbsentDirIsNoop(t *testing.T) {
	cfg := config.Config{Detectors: config.Detectors{Sidecars: config.Sidecars{Dir: filepath.Join(t.TempDir(), "does-not-exist")}}}
	if err := loadSidecarDetectors(cfg, ""); err != nil {
		t.Fatalf("absent sidecars dir must be a no-op, got error: %v", err)
	}
}

// TestLoadSidecarDetectors_InvalidModuleIsLoudError proves a present dir with
// an unloadable module is a hard failure, never a silently skipped sidecar.
func TestLoadSidecarDetectors_InvalidModuleIsLoudError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.wasm"), []byte("not a real wasm module"), 0o644); err != nil {
		t.Fatalf("write broken.wasm: %v", err)
	}
	cfg := config.Config{Detectors: config.Detectors{Sidecars: config.Sidecars{Dir: dir}}}
	if err := loadSidecarDetectors(cfg, ""); err == nil {
		t.Fatal("an invalid wasm module in the sidecars dir must be a loud load error")
	}
}
