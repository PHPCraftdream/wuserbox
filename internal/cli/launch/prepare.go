package launch

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/setup"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/grants"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// prepare loads the sandbox, building or repairing it with administrator
// rights when the group is missing or a permission cannot be applied as the
// plain user.
func prepare(options sandbox.Options) (*state.State, error) {
	name, _, err := sandbox.Name(options.Dir)
	if err != nil {
		return nil, err
	}
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if _, lookupErr := sid.Lookup(name); s == nil || lookupErr != nil {
		fmt.Fprintf(os.Stderr, "wuserbox: creating sandbox %s\n", name)
		return rebuild(options, name)
	}
	if options.NoAI {
		// The flag has to mean the same thing on every run, not only on the
		// one that created the sandbox.
		if err := grants.DropPreset(s); err != nil {
			fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
			return rebuild(options, name)
		}
	}
	if err := grants.FromConfig(s); err != nil {
		fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
		return rebuild(options, name)
	}
	if err := grants.Extra(s, options.RW, options.RO); err != nil {
		fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
		return rebuild(options, name)
	}
	return s, nil
}

func rebuild(options sandbox.Options, name string) (*state.State, error) {
	if err := setup.Elevate(options.Args()); err != nil {
		return nil, err
	}
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("sandbox %s was not created", name)
	}
	return s, nil
}
