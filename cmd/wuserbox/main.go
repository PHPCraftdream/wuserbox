// Command wuserbox runs a command in a write-restricted Windows sandbox: it
// reads everything the calling user can read, and writes only where a
// permission for the project's group allows it.
package main

import (
	"fmt"
	"os"

	"wuserbox/internal/cli"
)

func main() {
	useBundledLibrary()
	if err := cli.Execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "wuserbox:", err)
		os.Exit(1)
	}
}
