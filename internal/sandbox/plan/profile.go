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
//
// The destination comes from sandbox.ProfileDir(group), not from a loaded
// state record's own Profile field, and the two can never disagree: Profile
// is written in exactly one place, ensureProfile, and every time it is
// written it is set to this same ProfileDir(group) -- a pure function of the
// group name and nothing else, by its own doc. So there is no state a real
// run could be in where its s.Profile names a different directory than the
// one computed here. Recomputing it is not merely equivalent, though: a
// preview is also shown for a sandbox that does not exist yet, when there is
// no state record at all to read a Profile field from, and this still has to
// name the directory a first run would fill.
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
