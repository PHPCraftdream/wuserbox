package inspect

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

// Sandbox is one entry of the list, in the shape a program reads.
type Sandbox struct {
	Group string `json:"group"`
	Dir   string `json:"dir"`
}

// listFlags builds list's set, apart from the parsing, so a test can walk the
// flags the command really takes and hold the help to exactly those.
func listFlags() (*flag.FlagSet, *bool) {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	usage.Quiet(flags)
	return flags, flags.Bool("json", false, "print the list as JSON")
}

// List prints every sandbox on this machine.
func List(args []string) error {
	flags, asJSON := listFlags()
	if err := flags.Parse(args); err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
	}
	if flags.NArg() > 0 {
		return exit.Errorf(exit.Usage, "usage: wuserbox --list [--json]")
	}
	entries, err := group.List()
	if err != nil {
		return err
	}
	if *asJSON {
		sandboxes := make([]Sandbox, 0, len(entries))
		for _, e := range entries {
			sandboxes = append(sandboxes, Sandbox{Group: e.Name, Dir: e.Dir})
		}
		encoded, err := json.MarshalIndent(map[string]any{"sandboxes": sandboxes}, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(encoded, '\n'))
		return err
	}
	for _, e := range entries {
		fmt.Printf("%s\t%s\n", e.Name, e.Dir)
	}
	return nil
}
