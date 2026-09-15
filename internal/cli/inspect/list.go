package inspect

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

// Sandbox is one entry of the list, in the shape a program reads.
//
// A program is given the whole of it whatever form was asked for: --long
// decides how much a person is shown, and there is no reason to hand a
// parser less than is known. Everything past the first two fields is
// omitted when empty, which is how a reader tells "nothing was recorded"
// from "recorded as nothing".
type Sandbox struct {
	Group   string      `json:"group"`
	Dir     string      `json:"dir"`
	Account string      `json:"account,omitempty"`
	Profile string      `json:"profile,omitempty"`
	Temp    string      `json:"temp,omitempty"`
	Write   []string    `json:"write,omitempty"`
	Read    []string    `json:"read,omitempty"`
	Made    *time.Time  `json:"made,omitempty"`
	Used    *time.Time  `json:"used,omitempty"`
	Size    *SizeOnDisk `json:"size,omitempty"`
}

// listFlags builds list's set, apart from the parsing, so a test can walk the
// flags the command really takes and hold the help to exactly those.
func listFlags() (*flag.FlagSet, *bool, *bool) {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	usage.Quiet(flags)
	return flags,
		flags.Bool("json", false, "print the list as JSON"),
		flags.Bool("long", false, "print everything known about each sandbox, a block at a time")
}

// List prints every sandbox on this machine.
func List(args []string) error {
	flags, asJSON, asBlocks := listFlags()
	if err := flags.Parse(args); err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
	}
	if flags.NArg() > 0 {
		return exit.Errorf(exit.Usage, "usage: wuserbox --list [--long] [--json]")
	}
	entries, err := group.List()
	if err != nil {
		return err
	}
	return write(os.Stdout, describe(entries), *asJSON, *asBlocks)
}

// write puts the list out in whichever of the three forms was asked for.
func write(to io.Writer, sandboxes []Sandbox, asJSON, asBlocks bool) error {
	if asJSON {
		encoded, err := json.MarshalIndent(map[string]any{"sandboxes": sandboxes}, "", "  ")
		if err != nil {
			return err
		}
		_, err = to.Write(append(encoded, '\n'))
		return err
	}
	if asBlocks {
		_, err := io.WriteString(to, blocks(sandboxes))
		return err
	}
	// The plain form stays one line per sandbox: it is what gets read by eye
	// and cut up by other tools, and adding a column to it would break both.
	for _, s := range sandboxes {
		if _, err := fmt.Fprintf(to, "%s\t%s\n", s.Group, s.Dir); err != nil {
			return err
		}
	}
	return nil
}
