package access

import (
	"fmt"

	"wuserbox/internal/policy/config"
	"wuserbox/internal/policy/state"
	"wuserbox/internal/sandbox"
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
	if rule == nil || !rule.Remove(t.path) {
		return fmt.Errorf("%s is not listed for %s in %s", t.path, t.project, config.Path())
	}
	if err := rules.Save(); err != nil {
		return err
	}
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
