// Package diagnose answers questions about a sandbox without changing it:
// what it may touch, whether one particular thing would work, and whether the
// rules file makes sense.
package diagnose

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// Check answers whether a sandbox could do something to a path, by asking
// Windows rather than by trying it. Nothing is opened for writing and nothing
// is created, so the question is free of consequences.
//
// The answer is in the exit code as well as the output: allowed, refused, or
// the question could not be asked.
func Check(args []string) error {
	flags, o := checkFlags()
	options, operands := split(args)
	if err := flags.Parse(options); err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
	}
	if len(operands) != 1 {
		return exit.Errorf(exit.Usage,
			"usage: wuserbox --check <path> [--operation read|write|create|delete] [--dir project] [--json]")
	}
	wanted, err := access.Parse(o.operation)
	if err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
	}
	path, err := paths.Resolve(operands[0])
	if err != nil {
		return err
	}
	s, err := sandboxOf(o.dir)
	if err != nil {
		return err
	}
	who, err := whoToAsk(s)
	if err != nil {
		return err
	}
	result, err := access.Check(who, path, wanted)
	if err != nil {
		return err
	}
	if err := printCheck(result, o.asJSON); err != nil {
		return err
	}
	if !result.Allowed {
		return exit.Errorf(exit.Denied, "%s on %s is refused", result.Operation, result.Path)
	}
	return nil
}

// question is every flag check reads.
type question struct {
	operation string
	dir       string
	asJSON    bool
}

// checkFlags builds that set, apart from the parsing, so a test can walk the
// flags the command really takes and hold the help to exactly those.
func checkFlags() (*flag.FlagSet, *question) {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	usage.Quiet(flags)
	o := &question{}
	flags.StringVar(&o.operation, "operation", "write", "read, write, create or delete")
	flags.StringVar(&o.dir, "dir", "", "project whose sandbox is meant")
	flags.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
	return flags, o
}

func printCheck(result access.Result, asJSON bool) error {
	if asJSON {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(encoded, '\n'))
		return err
	}
	verdict := "refused"
	if result.Allowed {
		verdict = "allowed"
	}
	fmt.Printf("%s %s: %s\n", result.Operation, result.Path, verdict)
	if result.Checked != result.Path {
		fmt.Printf("  asked about %s\n", result.Checked)
	}
	fmt.Printf("  %s\n", result.Reason)
	return nil
}

// whoToAsk turns a sandbox's record into the thing every question here is
// put to: its group, its account, and that account's password with the seal
// off.
//
// The password is opened here rather than deeper down because opening it is
// this process's privilege and nothing else's -- it was sealed to the account
// that built the sandbox, so a record that reached this machine by some other
// route cannot be opened at all, and that is worth saying plainly rather than
// leaving as a DPAPI error about data that is perfectly fine.
func whoToAsk(s *state.State) (access.Sandbox, error) {
	who := access.Sandbox{Group: s.SID, Account: s.Account}
	if s.Account == "" {
		return who, nil // older sandbox: no account to log on as
	}
	if runningAsIt(s.Account) {
		// Asked from inside the sandbox itself, where the token is already in
		// hand and the seal on the password is not this account's to open.
		who.Inside = true
		return who, nil
	}
	password, err := acct.Unprotect(s.Secret)
	if err != nil {
		return who, exit.Errorf(exit.Failed,
			"the password for %s was sealed by a different account, so this one cannot ask "+
				"what %s may do; rebuild the sandbox with `wuserbox --init --dir %s`: %v",
			s.Account, s.Group, s.Dir, err)
	}
	who.Password = password
	return who, nil
}

// runningAsIt reports whether this process is the account it is being asked
// about.
//
// By identifier and not by the general "am I in a sandbox" test, because the
// two questions are different: a sandbox for one project asking about
// another's must not be answered with its own token, which would describe the
// wrong sandbox entirely.
func runningAsIt(account string) bool {
	me, err := sid.CurrentUser()
	if err != nil {
		return false
	}
	value, err := sid.Lookup(account)
	return err == nil && strings.EqualFold(value.String(), me)
}

// sandboxOf loads the bookkeeping of the sandbox a command is asking about.
func sandboxOf(project string) (*state.State, error) {
	if project == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		project = cwd
	}
	name, dir, err := sandbox.Name(project)
	if err != nil {
		return nil, err
	}
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, exit.Errorf(exit.NotFound,
			"no sandbox for %s yet; run `wuserbox --init` there", dir)
	}
	return s, nil
}

// split separates option arguments from plain ones, so their order does not
// matter. The flag package would stop at the first plain one.
func split(args []string) (options, operands []string) {
	withValue := map[string]bool{"operation": true, "dir": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) == 0 || arg[0] != '-' {
			operands = append(operands, arg)
			continue
		}
		options = append(options, arg)
		name := arg
		for len(name) > 0 && name[0] == '-' {
			name = name[1:]
		}
		if withValue[name] && i+1 < len(args) {
			i++
			options = append(options, args[i])
		}
	}
	return options, operands
}

// lower folds a path for use as a map key.
func lower(path string) string { return strings.ToLower(path) }
