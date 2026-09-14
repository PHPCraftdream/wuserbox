package access

import (
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
)

// RemoveDir forgets a directory in the standing rules and takes it back from
// the sandbox if it currently holds it.
func RemoveDir(args []string) error {
	t, err := parseTarget("remove-dir", args)
	if err != nil {
		return err
	}
	rules, err := config.Load()
	if err != nil {
		return err
	}
	rule := rules.RuleFor(t.project, false)
	if rule == nil {
		return exit.Errorf(exit.NotFound, "%s is not listed for %s in %s", t.path, t.project, config.Path())
	}
	if t.dryRun {
		if _, listed := rule.Kind(t.path); !listed {
			return t.preview()
		}
		return t.preview(
			plan.Action{Does: "forget", What: t.path, Detail: "in " + config.Path()},
			plan.Action{Does: "revoke", What: t.path},
		)
	}
	// One lock covers the rule and the permission it stands for, in the same
	// order add-dir takes them: the rules file first, the sandbox second.
	// Under two locks a gap opens between forgetting the rule and taking the
	// directory back, and an add-dir arriving in it leaves a permission behind
	// that no rule accounts for.
	return state.Locked(state.RulesLock, func() error {
		if err := forget(t); err != nil {
			return err
		}
		return revokeIfHeld(t)
	})
}

// revokeIfHeld takes the directory back when the sandbox holds it. A sandbox
// that never held it, or was never built, needs nothing here.
func revokeIfHeld(t target) error {
	name, _, err := sandbox.Name(t.project)
	if err != nil {
		return err
	}
	s, err := state.Load(name)
	if err != nil || s == nil || !s.Has(t.path) {
		return err
	}
	return Revoke([]string{t.path, "--dir", t.project})
}

// forget deletes the rule, with the rules file already held.
func forget(t target) error {
	rules, err := config.Load()
	if err != nil {
		return err
	}
	rule := rules.RuleFor(t.project, false)
	if rule == nil || !rule.Remove(t.path) {
		return exit.Errorf(exit.NotFound, "%s is not listed for %s in %s",
			t.path, t.project, config.Path())
	}
	return rules.Save()
}
