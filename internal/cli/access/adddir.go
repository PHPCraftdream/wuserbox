package access

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
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
		return t.preview(plannedRules(rules, t)...)
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

// plannedRules works out what add-dir would change, without changing it.
func plannedRules(rules *config.Config, t target) []plan.Action {
	var actions []plan.Action
	if rule := rules.RuleFor(t.project, false); rule != nil {
		if kind, listed := rule.Kind(t.path); listed {
			if kind == t.kind {
				return nil
			}
			actions = append(actions, plan.Action{
				Does: "change", What: t.path,
				Detail: string(kind) + " to " + string(t.kind) + " in " + config.Path(),
			})
			return append(actions, plan.Action{
				Does: "grant", What: t.path, Detail: string(t.kind),
			})
		}
	}
	actions = append(actions, plan.Action{
		Does: "record", What: t.path, Detail: string(t.kind) + " in " + config.Path(),
	})
	return append(actions, plan.Action{Does: "grant", What: t.path, Detail: string(t.kind)})
}
