// Command hang is a deliberately-hanging wasip1 test fixture for
// detecthost_test.go's TestDetectKillsHungGuest — it never returns, proving
// that a context deadline (wazero's RuntimeConfig.WithCloseOnContextDone)
// forcibly terminates a guest stuck in a pure CPU loop, not merely one blocked
// on I/O. It intentionally has NO dependency on pkg/detectorhost: the hang
// happens before any stdio protocol would even matter.
package main

func main() {
	for {
	}
}
