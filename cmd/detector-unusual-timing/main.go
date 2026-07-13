// detector-unusual-timing reads events JSONL from stdin and emits ONE finding
// JSONL line per distinct (actor, UTC hour) group whose hour is not seen for
// that actor in the baseline period (mallcoppro-d73 — collapsed from one
// finding per matching event, which used to fan out N findings for N events
// sharing a single novel actor-hour).
//
// Usage:
//
//	detector-unusual-timing --baseline <path> < events.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

func main() {
	baselinePath := flag.String("baseline", "", "path to baseline JSON file (required)")
	flag.Parse()

	if *baselinePath == "" {
		log.Fatal("--baseline is required")
	}

	bl, err := baseline.Load(*baselinePath)
	if err != nil {
		log.Fatalf("loading baseline: %v", err)
	}

	// Buffer the whole batch — grouping by (actor, hour) requires seeing every
	// event sharing a key before the group's finding (event_count, event_ids,
	// sources, event_types) can be emitted. Mirrors core/detect.Detect, which
	// is likewise whole-corpus, not a per-line stream.
	var events []event.Event
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Printf("skipping malformed event: %v", err)
			continue
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Fatalf("reading stdin: %v", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	for _, f := range collapse(events, bl) {
		if err := enc.Encode(f); err != nil {
			log.Fatalf("encoding finding: %v", err)
		}
	}
}
