// The slot a command holds on its sandbox for as long as it is changing what
// a concurrent run of the same sandbox stands on. It used to be taken inside
// proc.RunAsAccount, around the logon alone, and that placement was measured
// defending too little: a second run of a busy sandbox filled the shared
// profile first -- clearing whatever the rules file's cleanup globs name,
// which is how it deleted the files of a session that was still going --
// forgot the entries the list no longer named, recopied the rest, and only
// then reached the logon and was refused. A run's reach is wider than its
// launch, and how wide is only visible here, where a run is a command rather
// than a syscall, so the lease lives here now and covers all of it.

package setup

import (
	"errors"
	"fmt"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
)

// leaseWait is how long a command whose sandbox's slot is already held waits
// for it before being refused. Five seconds absorbs a first run in its last
// second and a script that fires two commands back to back; anything longer
// is a real concurrent session, and refusing it -- with the message below --
// beats hanging behind a first run that may be an agent session with hours
// left in it. lock.Lease carries the other half of that argument.
const leaseWait = 5 * time.Second

// holdSlot takes the sandbox's slot and returns how to let it go.
//
// A held slot is not a failure to retry blindly: the message below is the one
// a person sees, so it says what happened -- another run of this sandbox is
// going, and one run at a time is what keeps a stub out of a window a
// standing program can reach into -- and what to do about it.
func holdSlot(group string) (func(), error) {
	release, err := lock.Lease(group, leaseWait)
	if err != nil {
		if errors.Is(err, lock.ErrSlotHeld) {
			return nil, fmt.Errorf("another run of sandbox %s is already going, and a sandbox runs one thing at a time; "+
				"wait for that run to end -- or stop it -- then start this one again: %w", group, err)
		}
		return nil, fmt.Errorf("leasing the slot of sandbox %s: %w", group, err)
	}
	return release, nil
}
