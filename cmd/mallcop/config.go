package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/config"
)

// runConfig implements `mallcop config`: print the effective merged scan
// configuration resolved from a discovered mallcop.yaml overlaid with the
// environment. This is a SUPERSET of the old env-only print — with no config
// file present it still shows the MALLCOP_INFERENCE_URL / MALLCOP_API_KEY pivot,
// and it now additionally renders the store, connectors, detectors, learning
// dir, sovereignty, and budgets the config declares.
//
// Precedence for the inference block follows design §C.1 (env > config here;
// there are no flags in `mallcop config`). The rest is printed from the merged
// config (an absent file resolves to config.Defaults()).
func runConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides $"+config.EnvConfigPath+" and walk-up discovery)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, path, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Inference: env pivot (MALLCOP_INFERENCE_URL / _MODEL) overrides the config,
	// matching runScan's resolution order.
	url := config.Resolve(os.Getenv(envInferenceURL), cfg.Inference.Endpoint)
	model := config.Resolve(os.Getenv(envInferenceModel), cfg.Inference.Model, "mallcop-default")
	keyEnv := cfg.Inference.KeyEnv
	if keyEnv == "" {
		keyEnv = envInferenceKey
	}

	fmt.Printf("mallcop effective config\n\n")
	if path == "" {
		fmt.Printf("  Config file:          (none found — built-in defaults; run `mallcop init` to create %s)\n", config.ConfigFileName)
	} else {
		fmt.Printf("  Config file:          %s\n", path)
	}
	fmt.Printf("  Version:              %d\n\n", cfg.Version)

	fmt.Printf("  Inference mode:       %s\n", cfg.Inference.Mode)
	if url == "" {
		fmt.Printf("  Inference URL (%s):   (unset — scans force-escalate every finding, the fail-safe)\n", envInferenceURL)
	} else {
		fmt.Printf("  Inference URL (%s):   %s\n", envInferenceURL, url)
	}
	if os.Getenv(keyEnv) == "" {
		fmt.Printf("  Inference key (%s):       (unset)\n", keyEnv)
	} else {
		fmt.Printf("  Inference key (%s):       (set)\n", keyEnv)
	}
	fmt.Printf("  Model (%s):                 %s\n\n", envInferenceModel, model)

	fmt.Printf("  Store path:           %s\n", cfg.Store.Path)
	if cfg.Store.Baseline != "" {
		fmt.Printf("  Baseline:             %s\n", cfg.Store.Baseline)
	}

	fmt.Printf("  Connectors:           %d configured\n", len(cfg.Connectors))
	for _, c := range cfg.Connectors {
		fmt.Printf("    - %-16s kind=%s\n", c.ID, c.Kind)
	}

	fmt.Printf("  Builtin detectors:    enabled=%t disabled=%v\n", cfg.Detectors.Builtin.Enabled, cfg.Detectors.Builtin.Disable)
	fmt.Printf("  Learning dir:         %s (autonomy=%s, enforce_pin=%t)\n", cfg.Learning.Dir, cfg.Learning.Autonomy, cfg.Learning.EnforcePin)
	fmt.Printf("  Sovereignty:          tier=%s contribute_back=%t\n", cfg.Sovereignty.Tier, cfg.Sovereignty.ContributeBack)
	fmt.Printf("  Budgets:              max_findings=%d scan_timeout=%s selfext_spend_cap_usd=%.0f\n",
		cfg.Budgets.MaxFindings, cfg.Budgets.ScanTimeout, cfg.Budgets.SelfextSpendCapUSD)
	return nil
}
