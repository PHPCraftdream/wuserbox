package plan

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
)

// Input is what the plan is worked out from: the same choices a run is given.
type Input struct {
	Group      string
	Dir        string
	Temp       string
	RW, RO     []string
	NoAI       bool
	HomeWrites bool
}

// For works out what the sandbox would hold, in the order the permissions
// would be applied. Nothing is read from the sandbox itself and nothing is
// changed, so this is safe to call before a sandbox exists.
func For(in Input) (Plan, error) {
	p := Plan{Group: in.Group, Dir: in.Dir, Temp: in.Temp}
	p.add(in.Temp, grant.RW, FromTemp)
	p.add(in.Dir, grant.RW, FromProject)

	if !in.NoAI {
		for _, spec := range preset.AI() {
			p.add(spec.Path, spec.Kind, FromPreset)
		}
		if in.HomeWrites {
			home := preset.Home()
			p.add(home.Path, home.Kind, FromPreset)
			p.Reserved = preset.Missing()
			p.Unreserved = preset.Shadowable()
		}
	}

	rules, err := config.Load()
	if err != nil {
		return Plan{}, err
	}
	for _, spec := range rules.GrantsFor(in.Dir) {
		if _, err := os.Stat(spec.Path); err != nil {
			continue
		}
		p.add(spec.Path, spec.Kind, FromRules)
	}

	for _, list := range []struct {
		dirs []string
		kind grant.Kind
	}{{in.RW, grant.RW}, {in.RO, grant.RO}} {
		for _, dir := range list.dirs {
			resolved, err := paths.Resolve(dir)
			if err != nil {
				return Plan{}, err
			}
			p.add(resolved, list.kind, FromFlags)
		}
	}
	return p, nil
}

// add records a directory, replacing an earlier entry for the same path, so
// the plan shows the access that would actually end up in force.
func (p *Plan) add(path string, kind grant.Kind, source Source) {
	clean := filepath.Clean(path)
	for i := range p.Entries {
		if paths.Same(p.Entries[i].Path, clean) {
			p.Entries[i].Kind = kind
			p.Entries[i].Source = source
			return
		}
	}
	p.Entries = append(p.Entries, Entry{Path: clean, Kind: kind, Source: source})
}
