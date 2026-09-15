// Command wuserbox runs a command on Windows so that it reads everything the
// calling user can read and changes nothing the machine does not already let
// every local account change, anywhere it was not granted. The exception is
// named rather than glossed over: a directory already open to Everyone or
// BUILTIN\Users stays open, because a sandbox has to carry both to start a
// program and read the system at all. `wuserbox --audit` lists them; the
// README sets out what that is worth.
package main

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/cli"
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
