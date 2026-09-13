package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// libraryName is the parser library the configuration format needs, named for
// the architecture this build targets.
var libraryName = fmt.Sprintf("ktav_cabi-windows-%s.dll", runtime.GOARCH)

// libraryVariable is where the ktav bindings look for an explicit location.
const libraryVariable = "KTAV_LIB_PATH"

// useBundledLibrary points the parser at the copy shipped beside the
// executable, when there is one. Without it the bindings download the library
// on first use, which fails on a machine with no network.
func useBundledLibrary() {
	if os.Getenv(libraryVariable) != "" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		return
	}
	bundled := filepath.Join(filepath.Dir(executable), libraryName)
	if _, err := os.Stat(bundled); err == nil {
		os.Setenv(libraryVariable, bundled)
	}
}
