// Command sidecar-detector is the example wasip1 sidecar main: it is compiled
// with GOOS=wasip1 GOARCH=wasm and run inside the wazero host
// (github.com/mallcop-app/mallcop/detecthost), never invoked as a native
// binary. It is the whole AI-authored surface a self-extension loop sidecar
// would ship — everything else (the stdio wire protocol) is owned by
// pkg/detectorhost.
package main

import (
	"os"

	"github.com/mallcop-app/mallcop/examples/sidecar-detector/exampledetector"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
)

func main() {
	os.Exit(detectorhost.Run(exampledetector.Detector{}))
}
