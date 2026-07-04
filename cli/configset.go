package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/mallcop-app/mallcop/core/config"
)

// runConfigSet implements `mallcop config set connector ...` and
// `mallcop config set autonomy <value>` — the "linux-mode" CLI surface over
// the SHARED mutation primitive (core/config.AddConnector / SetAutonomy).
// This function does no mutation itself: it only parses flags into a
// Connector / autonomy string and hands off to the primitive, so any other
// driver of the same change (a chat surface) that calls the same primitive
// functions is, by construction, doing exactly what this command does.
func runConfigSet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("config set requires a target: \"connector\" or \"autonomy\"")
	}
	target := args[0]
	rest := args[1:]

	switch target {
	case "connector":
		return runConfigSetConnector(rest)
	case "autonomy":
		return runConfigSetAutonomy(rest)
	default:
		return fmt.Errorf("config set: unknown target %q (want \"connector\" or \"autonomy\")", target)
	}
}

func runConfigSetConnector(args []string) error {
	fs := flag.NewFlagSet("config set connector", flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides $"+config.EnvConfigPath+" and walk-up discovery)")
	kind := fs.String("kind", "", "Connector kind: file | github | cloud (required)")
	id := fs.String("id", "", "Connector id — must be unique (required)")
	path := fs.String("path", "", "Events JSONL path (kind=file)")
	org := fs.String("org", "", "GitHub org (kind=github)")
	source := fs.String("source", "", "Cloud source name (kind=cloud)")
	binary := fs.String("binary", "", "Explicit sibling binary override (kind=cloud)")
	since := fs.String("since", "", "Since cursor (kind=cloud)")
	argsCSV := fs.String("args", "", "Comma-separated exec args (kind=cloud)")
	envCSV := fs.String("env", "", "Comma-separated env-var NAMES the connector reads (never inline secrets)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	conn := config.Connector{
		Kind:   *kind,
		ID:     *id,
		Path:   *path,
		Org:    *org,
		Source: *source,
		Binary: *binary,
		Since:  *since,
		Args:   splitCSV(*argsCSV),
		Env:    splitCSV(*envCSV),
	}

	cfg, resolvedPath, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("config set connector: %w", err)
	}
	if resolvedPath == "" {
		return fmt.Errorf("config set connector: no %s found (run `mallcop init` first, or pass --config)", config.ConfigFileName)
	}

	next, err := config.AddConnector(cfg, conn)
	if err != nil {
		return fmt.Errorf("config set connector: %w", err)
	}
	if err := config.WriteConfigAtomic(resolvedPath, next); err != nil {
		return fmt.Errorf("config set connector: %w", err)
	}

	fmt.Printf("mallcop config set connector: added %q (kind=%s) to %s — takes effect on the next `mallcop scan`\n", conn.ID, conn.Kind, resolvedPath)
	return nil
}

func runConfigSetAutonomy(args []string) error {
	fs := flag.NewFlagSet("config set autonomy", flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to mallcop.yaml (overrides $"+config.EnvConfigPath+" and walk-up discovery)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("config set autonomy: expected exactly one value (%q, %q, or %q)", config.AutonomyNon, config.AutonomySemi, config.AutonomyFully)
	}
	value := fs.Arg(0)

	cfg, resolvedPath, err := config.LoadEffective(*configPath)
	if err != nil {
		return fmt.Errorf("config set autonomy: %w", err)
	}
	if resolvedPath == "" {
		return fmt.Errorf("config set autonomy: no %s found (run `mallcop init` first, or pass --config)", config.ConfigFileName)
	}

	next, err := config.SetAutonomy(cfg, value)
	if err != nil {
		return fmt.Errorf("config set autonomy: %w", err)
	}
	if err := config.WriteConfigAtomic(resolvedPath, next); err != nil {
		return fmt.Errorf("config set autonomy: %w", err)
	}

	fmt.Printf("mallcop config set autonomy: learning.autonomy=%s in %s\n", value, resolvedPath)
	return nil
}

// splitCSV splits a comma-separated flag value into a trimmed, non-empty
// slice; an empty input yields nil (so an omitted --env/--args flag leaves
// the Connector field as the zero value, not an empty-but-non-nil slice).
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
