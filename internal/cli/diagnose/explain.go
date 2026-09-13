package diagnose

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
)

// Account is one directory a sandbox holds, why it holds it, and whether the
// permission is really in place.
type Account struct {
	Path   string      `json:"path"`
	Kind   grant.Kind  `json:"kind"`
	Source plan.Source `json:"source"`
	// InForce is what Windows says when asked, which is not always what the
	// bookkeeping claims: a directory may have been removed, or its
	// permissions changed by hand.
	InForce bool   `json:"in_force"`
	Note    string `json:"note,omitempty"`
}

// Report is the whole answer explain gives.
type Report struct {
	Group    string    `json:"group"`
	Dir      string    `json:"dir"`
	Temp     string    `json:"temp"`
	Accounts []Account `json:"permissions"`
	// Drifted lists the paths where the bookkeeping and Windows disagree.
	Drifted []string `json:"drifted,omitempty"`
}

// Explain prints what a sandbox may touch and where each permission came
// from, and checks each one against Windows rather than trusting the record.
func Explain(args []string) error {
	flags := flag.NewFlagSet("explain", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { _, _ = io.WriteString(os.Stderr, usage.Text) }
	project := flags.String("dir", "", "project to explain")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	if err := flags.Parse(args); err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
	}
	s, err := sandboxOf(*project)
	if err != nil {
		return err
	}
	report, err := build(s)
	if err != nil {
		return err
	}
	return printReport(report, *asJSON)
}

func build(s *state.State) (Report, error) {
	report := Report{Group: s.Group, Dir: s.Dir, Temp: s.Temp}
	sources, err := sourcesFor(s)
	if err != nil {
		return report, err
	}
	for _, held := range s.Grants {
		account := Account{
			Path:   held.Path,
			Kind:   held.Kind,
			Source: sources[lower(held.Path)],
		}
		if account.Source == "" {
			account.Source = "given once"
		}
		account.InForce, account.Note = inForce(s.SID, held)
		report.Accounts = append(report.Accounts, account)
		if !account.InForce {
			report.Drifted = append(report.Drifted, held.Path)
		}
	}
	return report, nil
}

// sourcesFor works out where each permission would come from if the sandbox
// were built now, so a directory given once by hand can be told apart from one
// the rules file asks for every time.
func sourcesFor(s *state.State) (map[string]plan.Source, error) {
	prepared, err := plan.For(plan.Input{Group: s.Group, Dir: s.Dir, Temp: s.Temp})
	if err != nil {
		return nil, err
	}
	out := map[string]plan.Source{}
	for _, entry := range prepared.Entries {
		out[lower(entry.Path)] = entry.Source
	}
	return out, nil
}

// inForce asks Windows what the sandbox can really do with a path, and
// compares it with what was recorded.
//
// Both directions matter. Less access than recorded means a permission was
// lost. More access than recorded is the worse of the two: a directory
// written down as readable that the sandbox can in fact write to is exactly
// the situation this tool exists to prevent, and it would otherwise be
// reported as being in good order.
func inForce(account string, held grant.Spec) (bool, string) {
	readable, err := access.Check(account, held.Path, access.Read)
	if err != nil {
		return false, err.Error()
	}
	if !readable.Allowed {
		return false, "cannot be read: " + readable.Reason
	}
	// Each kind is tested by the operation that shows it is in force, not by
	// one operation for all of them: a permission meant to create files in a
	// directory without creating subdirectories would fail a plain write and
	// look broken while working exactly as intended.
	proving, err := access.Parse(held.Kind.Proves())
	if err != nil {
		return false, err.Error()
	}
	granted, err := access.Check(account, held.Path, proving)
	if err != nil {
		return false, err.Error()
	}
	if held.Kind.Writable() {
		if !granted.Allowed {
			return false, "recorded as writable, but " + string(proving) + " is refused: " + granted.Reason
		}
		return true, ""
	}
	// For a read-only entry the question is the other way round: writing has
	// to be refused, or the record is claiming less than the sandbox holds.
	writable, err := access.Check(account, held.Path, access.Write)
	if err != nil {
		return false, err.Error()
	}
	if writable.Allowed {
		return false, "recorded as read-only, but the sandbox can write to it"
	}
	return true, ""
}

func printReport(report Report, asJSON bool) error {
	if asJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(encoded, '\n'))
		return err
	}
	fmt.Printf("sandbox   %s\nproject   %s\ntemp      %s\n", report.Group, report.Dir, report.Temp)
	fmt.Printf("\npermissions\n")
	for _, account := range report.Accounts {
		state := "ok"
		if !account.InForce {
			state = "not in force"
		}
		fmt.Printf("  %-4s %s\n        from %s, %s\n", account.Kind, account.Path, account.Source, state)
		if account.Note != "" {
			fmt.Printf("        %s\n", account.Note)
		}
	}
	if len(report.Drifted) > 0 {
		fmt.Printf("\n%d recorded permission(s) are not in force; `wuserbox init` reapplies them\n",
			len(report.Drifted))
	}
	return nil
}
