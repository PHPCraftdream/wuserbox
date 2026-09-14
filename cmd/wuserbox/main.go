// Command wuserbox runs a command in a write-restricted Windows sandbox: it
// reads everything the calling user can read, and writes only where a
// permission for the project's group allows it.
package main

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
)

func main() {
	useBundledLibrary()
	args := os.Args[1:]
	if err := cli.Execute(args); err != nil {
		// Reported the way it was asked for: a command called with --json
		// answers in JSON whether it worked or not.
		exit.Report(os.Stderr, err, exit.JSONAsked(args))
		os.Exit(int(exit.Of(err)))
	}
}
