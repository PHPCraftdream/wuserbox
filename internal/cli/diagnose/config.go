package diagnose

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
)

// Complaint is one thing wrong with the rules file.
type Complaint struct {
	// Kind is what sort of problem it is, so a script can sort them:
	// "syntax", "conflict", "duplicate" or "missing".
	Kind    string `json:"kind"`
	Project string `json:"project,omitempty"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Config reads the rules file: show it, say where it is, or check it.
func Config(args []string) error {
	if len(args) == 0 {
		return exit.Errorf(exit.Usage, "usage: wuserbox config show|path|validate [--dir project] [--json]")
	}
	action, rest := args[0], args[1:]
	flags := flag.NewFlagSet("config "+action, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { _, _ = io.WriteString(os.Stderr, usage.Text) }
	project := flags.String("dir", "", "show the rule for one project only")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	if err := flags.Parse(rest); err != nil {
		return err
	}
	switch action {
	case "path":
		fmt.Println(config.Path())
		return nil
	case "show":
		return showRules(*project, *asJSON)
	case "validate":
		return validateRules(*asJSON)
	default:
		return exit.Errorf(exit.Usage, "unknown config action %q (show, path or validate)", action)
	}
}

func showRules(project string, asJSON bool) error {
	rules, err := config.Load()
	if err != nil {
		return exit.Errorf(exit.BadConfig, "%v", err)
	}
	if project != "" {
		_, dir, err := sandbox.Name(project)
		if err != nil {
			return err
		}
		rule := rules.RuleFor(dir, false)
		if rule == nil {
			return exit.Errorf(exit.NotFound, "%s has no rule in %s", dir, config.Path())
		}
		rules = &config.Config{Projects: []config.Rule{*rule}}
	}
	if asJSON {
		encoded, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(encoded, '\n'))
		return err
	}
	if len(rules.Projects) == 0 {
		fmt.Printf("%s holds no rules\n", config.Path())
		return nil
	}
	for _, rule := range rules.Projects {
		fmt.Println(rule.Dir)
		for _, listed := range rule.RW {
			fmt.Printf("  rw  %s\n", listed)
		}
		for _, listed := range rule.RO {
			fmt.Printf("  ro  %s\n", listed)
		}
	}
	return nil
}

func validateRules(asJSON bool) error {
	rules, err := config.Load()
	if err != nil {
		complaints := []Complaint{{Kind: "syntax", Message: err.Error()}}
		if printErr := printComplaints(complaints, asJSON); printErr != nil {
			return printErr
		}
		return exit.Errorf(exit.BadConfig, "%s does not parse", config.Path())
	}
	complaints := inspectRules(rules)
	if err := printComplaints(complaints, asJSON); err != nil {
		return err
	}
	for _, complaint := range complaints {
		if complaint.Kind != "missing" {
			return exit.Errorf(exit.BadConfig, "%s has %d problem(s)", config.Path(), len(complaints))
		}
	}
	return nil
}

// inspectRules looks for the mistakes a hand-edited file collects: the same
// directory twice, one directory in both lists, and directories that are no
// longer there. The last is reported apart from the rest, because it is not a
// mistake in the file.
func inspectRules(rules *config.Config) []Complaint {
	var complaints []Complaint
	for _, rule := range rules.Projects {
		seen := map[string]grant.Kind{}
		for _, list := range []struct {
			paths []string
			kind  grant.Kind
		}{{rule.RW, grant.RW}, {rule.RO, grant.RO}} {
			for _, listed := range list.paths {
				key := lower(cleanPath(listed))
				if previous, repeated := seen[key]; repeated {
					complaints = append(complaints, clash(rule.Dir, listed, previous, list.kind))
					continue
				}
				seen[key] = list.kind
				if _, err := os.Stat(cleanPath(listed)); err != nil {
					complaints = append(complaints, Complaint{
						Kind: "missing", Project: rule.Dir, Path: listed,
						Message: fmt.Sprintf("%s does not exist and will be skipped", listed),
					})
				}
			}
		}
	}
	return complaints
}

// clash describes a directory listed twice: either the same way, which is
// merely untidy, or both ways, which silently costs write access because the
// readable entry is applied last.
func clash(project, path string, previous, current grant.Kind) Complaint {
	if previous == current {
		return Complaint{
			Kind: "duplicate", Project: project, Path: path,
			Message: fmt.Sprintf("%s is listed twice as %s", path, current),
		}
	}
	return Complaint{
		Kind: "conflict", Project: project, Path: path,
		Message: fmt.Sprintf("%s is listed as both writable and readable; "+
			"the readable entry would win and write access would be lost", path),
	}
}

func cleanPath(path string) string {
	resolved, err := paths.Resolve(path)
	if err != nil {
		return path
	}
	return resolved
}

func printComplaints(complaints []Complaint, asJSON bool) error {
	if asJSON {
		if complaints == nil {
			complaints = []Complaint{}
		}
		encoded, err := json.MarshalIndent(map[string]any{"problems": complaints}, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(encoded, '\n'))
		return err
	}
	if len(complaints) == 0 {
		fmt.Printf("%s is in order\n", config.Path())
		return nil
	}
	for _, complaint := range complaints {
		fmt.Printf("%s: %s\n", complaint.Kind, complaint.Message)
		if complaint.Project != "" {
			fmt.Printf("  in the rule for %s\n", complaint.Project)
		}
	}
	return nil
}
