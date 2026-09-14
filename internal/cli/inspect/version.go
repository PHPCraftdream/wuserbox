package inspect

import (
	"fmt"
	"runtime"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
)

// Release is the version this executable was built from. The release build
// replaces it through the linker; a local build reports "dev".
var Release = "dev"

// Version prints the release and the platform it was built for.
func Version(args []string) error {
	if len(args) > 0 {
		return exit.Errorf(exit.Usage, "usage: wuserbox --version")
	}
	fmt.Printf("wuserbox %s (%s/%s, %s)\n", Release, runtime.GOOS, runtime.GOARCH, runtime.Version())
	return nil
}
