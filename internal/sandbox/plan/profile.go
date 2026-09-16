package plan

import (
	"github.com/PHPCraftdream/wuserbox/internal/policy/profile"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
)

// AddProfilePreview fills in what filling this sandbox's own profile would
// do, without doing any of it: see profile.Plan, which this only wires a
// group name and its kept fingerprints into.
//
// Called separately from For, rather than folded into it, because most
// callers of For never need this. explain asks only where each permission
// comes from, many times over one process's life; building this answer
// means reading the fingerprints kept for the sandbox and walking every
// profile: entry's source on the machine, a cost worth paying for the one
// command -- --dry-run -- this is actually for.
//
// noAI mirrors fillProfile's own branch in internal/cli/setup/run.go: a
// sandbox told to skip the agent preset never has its profile: entries
// copied, only cleared, so there is nothing to preview here either.
func (p *Plan) AddProfilePreview(group string, noAI bool) error {
	if noAI {
		return nil
	}
	prints, err := facts.Prints(group)
	if err != nil {
		return err
	}
	cleanupPlan, entryPlans, err := profile.Plan(sandbox.ProfileDir(group), prints)
	if err != nil {
		return err
	}
	p.Cleanup = cleanupPlan
	p.Profile = entryPlans
	return nil
}
