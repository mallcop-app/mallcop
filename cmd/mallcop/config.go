package main

import (
	"flag"
	"fmt"
	"os"
)

// runConfig implements `mallcop config`: print the effective scan configuration
// resolved from the environment. There is no chart or TOML config file — a scan
// is configured entirely by flags plus the MALLCOP_INFERENCE_URL / MALLCOP_API_KEY
// env pivot (point the URL at a vendor for BYOK, or at Forge for the metered
// managed path). This command shows what a scan would pick up right now.
func runConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	url := os.Getenv(envInferenceURL)
	model := os.Getenv(envInferenceModel)
	if model == "" {
		model = "mallcop-default"
	}

	fmt.Printf("mallcop effective config\n\n")
	if url == "" {
		fmt.Printf("  Inference URL (%s):   (unset — scans force-escalate every finding, the fail-safe)\n", envInferenceURL)
	} else {
		fmt.Printf("  Inference URL (%s):   %s\n", envInferenceURL, url)
	}
	if os.Getenv(envInferenceKey) == "" {
		fmt.Printf("  Inference key (%s):       (unset)\n", envInferenceKey)
	} else {
		fmt.Printf("  Inference key (%s):       (set)\n", envInferenceKey)
	}
	fmt.Printf("  Model (%s):                 %s\n", envInferenceModel, model)
	return nil
}
