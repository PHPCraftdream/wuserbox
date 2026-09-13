package access

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
)

// AddDir records a directory in the standing rules for this project, so every
// later run grants it, and grants it now if the sandbox already exists.
func AddDir(args []string) error {
	t, err := parseTarget("add-dir", args)
	if err != nil {
		return err
	}
	if info, err := os.Stat(t.path); err != nil || !info.IsDir() {
		return exit.Errorf(exit.Usage, "%s is not a directory", t.path)
	}
	rules, err := config.Load()
	if err != nil {
		return err
	}
	if t.dryRun {
		held, _ := load(t.project) // a sandbox that does not exist yet holds nothing
		return t.preview(planned(rules, held, t)...)
	}
	rule := rules.RuleFor(t.project, true)
	if rule.Add(t.path, t.kind) {
		if err := rules.Save(); err != nil {
			return err
		}
	}
	fmt.Printf("%s: %s -> %s (%s)\n", config.Path(), t.project, t.path, t.kind)

	name, _, err := sandbox.Name(t.project)
	if err != nil {
		return err
	}
	s, err := state.Load(name)
	if err != nil || s == nil {
		return err // not initialized yet: the next run picks the rule up
	}
	return Grant(t.args("grant")[1:])
}

// planned works out what add-dir would change, without changing it. Both
// halves of the command are considered: the rules file and the permission the
// sandbox holds today. Looking only at the rules used to report "nothing to
// do" for a command that went on to change an access control entry.
func planned(rules *config.Config, held *state.State, t target) []plan.Action {
	var actions []plan.Action

	listed, inRules := grant.Kind(""), false
	if rule := rules.RuleFor(t.project, false); rule != nil {
		listed, inRules = rule.Kind(t.path)
	}
	switch {
	case !inRules:
		actions = append(actions, plan.Action{
			Does: "record", What: t.path, Detail: string(t.kind) + " in " + config.Path(),
		})
	case listed != t.kind:
		actions = append(actions, plan.Action{
			Does: "change", What: t.path,
			Detail: string(listed) + " to " + string(t.kind) + " in " + config.Path(),
		})
	}

	if held == nil {
		// Without a sandbox the rule is all there is to change; the next run
		// applies it.
		return actions
	}
	current, granted := held.Kind(t.path)
	switch {
	case !granted:
		actions = append(actions, plan.Action{
			Does: "grant", What: t.path, Detail: string(t.kind),
		})
	case current != t.kind:
		actions = append(actions, plan.Action{
			Does: "change", What: t.path,
			Detail: string(current) + " to " + string(t.kind) + " for " + held.Group,
		})
	}
	return actions
}
