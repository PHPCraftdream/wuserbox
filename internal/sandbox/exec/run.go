// Package exec starts a command inside a prepared sandbox.
package exec

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Run executes a command in the sandbox described by s and returns its exit
// code.
//
// A sandbox this version of wuserbox built has its own local account
// (s.Account), starts as it through CreateProcessWithLogonW, and then runs
// under a token restricted to that account's own identities. The two are not
// alternatives, though they were treated as such for a while: see
// docs/design/an-account-of-its-own.md and
// docs/investigations/msys-under-a-restricted-token.md. A restricted token
// alone was what MSYS programs could not start under, because the objects an
// MSYS runtime builds around "the current user" name a user the token was
// forbidden to name -- its own process token among them. Under an account
// they name the account, which the token may name, so the restriction costs
// nothing and closes what being a separate account does not: everything the
// machine hands to Everyone, INTERACTIVE and the rest of the crowd.
//
// A sandbox an earlier version built has no account yet -- s.Account stays
// empty until `--init` runs again to add one -- and keeps running the old
// way meanwhile, rather than refusing to run until it is upgraded.
func Run(s *state.State, commandLine string) (int, error) {
	if s.Account == "" {
		return runRestricted(s, commandLine)
	}
	return runAsAccount(s, commandLine)
}

// runRestricted is what every run did before this sandbox had an account of
// its own, kept for one still without it.
//
// It is also what lets the delete-boundary tests exercise this same function
// with a synthetic SID and no administrator rights, by giving a state.State
// no account either. What that shows is the second of the two access checks,
// which is the same one either way; what it cannot show is named in
// token.Restricted, and is why internal/e2e/account_test.go exists alongside.
func runRestricted(s *state.State, commandLine string) (int, error) {
	restricted, err := token.Restricted(s.SID)
	if err != nil {
		return -1, err
	}
	defer restricted.Close()

	_ = os.Setenv("TEMP", s.Temp)
	_ = os.Setenv("TMP", s.Temp)
	_ = os.Setenv("WUSERBOX_GROUP", s.Group)
	_ = os.Setenv("WUSERBOX_DIR", s.Dir)
	return proc.Run(restricted, commandLine, s.Dir)
}

// runAsAccount starts commandLine as the sandbox's own account, with its
// profile loaded and an environment built to point inside that profile
// rather than the caller's own.
//
// What the account starts is not the program but wuserbox, which narrows its
// own token before starting it: being the account keeps a sandbox apart from
// the person who owns the machine, and the token keeps it away from what
// every account on the machine shares. See stub.go for why the second half
// cannot be arranged from here.
func runAsAccount(s *state.State, commandLine string) (int, error) {
	self, err := whereIAm()
	if err != nil {
		return -1, err
	}
	password, err := account.Unprotect(s.Secret)
	if err != nil {
		// The seal is tied to the account that made it, so the one way to
		// hold this record and not be able to open it is to be somebody
		// else -- which means the sandbox was built by another account and
		// its record reached this one by some route wuserbox did not take.
		// Said here rather than left as a DPAPI error code, because that
		// code says "the data is invalid" and the data is fine.
		return -1, fmt.Errorf(
			"the password for %s was sealed by a different account and cannot be opened by this one; "+
				"rebuild the sandbox with `wuserbox --init --dir %s`: %w",
			s.Account, s.Dir, err)
	}
	line, err := StubLine(self, s.SID, commandLine)
	if err != nil {
		return -1, err
	}
	code, err := proc.RunAsAccountWithLease(s.Account, password, line, s.Dir,
		childEnv(s, profileOf(s)), lock.SlotPath(s.Group))
	if err != nil {
		return -1, cannotStart(s, self, err)
	}
	return code, nil
}

// profileOf is where the sandbox's own thin profile lives. `--init` fills
// s.Profile in as part of building the account; sandbox.ProfileDir is the
// same pure function of the group name it is filled in with, kept as a
// fallback for the gap between a sandbox getting an account and getting a
// profile alongside it -- init.go runs both in the same build, but an older
// record on disk may still carry one without the other.
func profileOf(s *state.State) string {
	if s.Profile != "" {
		return s.Profile
	}
	return sandbox.ProfileDir(s.Group)
}

// childEnv is the environment handed to the sandboxed process: this
// process's own environment, so PATH and everything else that makes a
// program runnable still reaches it, but with the profile-rooted variables
// replaced to point inside the sandbox's own profile instead of the
// caller's, and WUSERBOX_GROUP/WUSERBOX_DIR set the same as they always
// were.
func childEnv(s *state.State, profileDir string) []string {
	// AppData\Local, AppData\Roaming and Temp are the three subdirectories
	// account.MakeProfile creates under profileDir; Temp sits at the
	// profile's own top level rather than under AppData\Local the way a
	// Windows-made profile lays it out, since nothing here has to match
	// that shape and a shorter path is one less thing to build.
	overrides := map[string]string{
		"USERPROFILE":    profileDir,
		"HOME":           profileDir,
		"APPDATA":        filepath.Join(profileDir, "AppData", "Roaming"),
		"LOCALAPPDATA":   filepath.Join(profileDir, "AppData", "Local"),
		"TEMP":           filepath.Join(profileDir, "Temp"),
		"TMP":            filepath.Join(profileDir, "Temp"),
		"WUSERBOX_GROUP": s.Group,
		"WUSERBOX_DIR":   s.Dir,
		// Windows fills these in from the logon only when it builds the
		// environment itself. An explicit block is taken as given, so
		// leaving them inherited would tell a program running as the
		// sandbox that it is the caller -- and HOMEDRIVE with HOMEPATH is
		// where git, among others, looks for a home when HOME is unset,
		// which would send it back to the profile this exists to keep it
		// out of.
		"USERNAME":   s.Account,
		"USERDOMAIN": os.Getenv("COMPUTERNAME"),
		"HOMEDRIVE":  filepath.VolumeName(profileDir),
		"HOMEPATH":   strings.TrimPrefix(profileDir, filepath.VolumeName(profileDir)),
	}
	inherited := os.Environ()
	out := make([]string, 0, len(inherited)+len(overrides))
	for _, kv := range inherited {
		key, _, found := strings.Cut(kv, "=")
		if !found {
			continue
		}
		if _, replaced := overrides[strings.ToUpper(key)]; replaced {
			continue
		}
		out = append(out, kv)
	}
	// Sorted, because ranging a map orders them differently every run and an
	// environment that changes shape between two identical runs is one more
	// thing to rule out when a run behaves differently from the last.
	for _, k := range slices.Sorted(maps.Keys(overrides)) {
		out = append(out, k+"="+overrides[k])
	}
	return out
}
