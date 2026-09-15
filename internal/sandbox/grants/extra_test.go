// Tests for what a sandbox is given besides the preset: the directories the
// rules file names, and the machine-wide group that lets it read the profile.
// The helpers shared by the files beside this one live here.

package grants

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

const testAccount = "S-1-5-21-1111111111-2222222222-3333333333-778899"

// TestMain loads the ktav parser before any test moves LOCALAPPDATA. The
// parser caches a native library under that directory and keeps it open, which
// would otherwise leave a temporary directory undeletable.
func TestMain(m *testing.M) {
	warm, err := os.CreateTemp("", "wuserbox-warm-*.ktav")
	if err == nil {
		_, _ = warm.WriteString("projects: [\n]\n")
		warm.Close()
		os.Setenv(config.EnvPath, warm.Name())
		_, _ = config.Load() // reaches the parser, which loads its library once
		os.Remove(warm.Name())
		os.Unsetenv(config.EnvPath)
	}
	os.Exit(m.Run())
}

func newState(t *testing.T) *state.State {
	t.Helper()
	t.Setenv("LOCALAPPDATA", tempDir(t))
	return &state.State{
		Group: "wub-grants-test",
		SID:   testAccount,
		Dir:   tempDir(t),
		Temp:  tempDir(t),
	}
}

// tempDir is t.TempDir() with the path reduced to one spelling, the way every
// command reduces the paths it is given. Some machines hand out a temporary
// directory under a shortened name, and comparing one spelling against another
// would fail there for a reason that has nothing to do with what is being
// tested.
func tempDir(t *testing.T) string {
	t.Helper()
	resolved, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestExtraGrantsBothKinds(t *testing.T) {
	s := newState(t)
	writable, readable := tempDir(t), tempDir(t)
	if err := Extra(s, []string{writable}, []string{readable}, false); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 2 {
		t.Fatalf("recorded %+v", s.Grants)
	}
	if s.Grants[0].Kind != grant.RW || s.Grants[1].Kind != grant.RO {
		t.Errorf("kinds are %q and %q", s.Grants[0].Kind, s.Grants[1].Kind)
	}
}

func TestExtraAcceptsShellStylePaths(t *testing.T) {
	s := newState(t)
	dir := tempDir(t)
	shellStyle := "/" + strings.ToLower(dir[:1]) + filepath.ToSlash(dir[2:])
	if err := Extra(s, []string{shellStyle}, nil, false); err != nil {
		t.Fatal(err)
	}
	if !s.Has(dir) {
		t.Errorf("recorded %+v, want %s", s.Grants, dir)
	}
}

func TestFromConfigSkipsDirectoriesThatAreGone(t *testing.T) {
	s := newState(t)
	present := tempDir(t)
	missing := filepath.Join(tempDir(t), "removed")
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "rules.ktav"))

	rules := &config.Config{Projects: []config.Rule{{Dir: s.Dir, RW: []string{present, missing}}}}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	if err := FromConfig(s, false); err != nil {
		t.Fatal(err)
	}
	if !s.Has(present) {
		t.Error("the directory that exists was not granted")
	}
	if s.Has(missing) {
		t.Error("a directory that no longer exists was granted")
	}
}

func TestFromConfigIsHarmlessWithoutRules(t *testing.T) {
	s := newState(t)
	t.Setenv(config.EnvPath, filepath.Join(tempDir(t), "none.ktav"))
	if err := FromConfig(s, false); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 0 {
		t.Errorf("recorded %+v", s.Grants)
	}
}

// TestEnsureReadableGrantsADirectoryNobodyCouldRead covers the half that
// matters on every run: a directory the group cannot read gets the permission,
// and one it can read already is left alone.
//
// The directory is protected first, which is the shape of a real Windows
// profile — its owner, the system and administrators, and nothing else — so
// the question is the same here as it is there.
func TestEnsureReadableGrantsADirectoryNobodyCouldRead(t *testing.T) {
	// Any group will do: what is under test is the mechanism, not which group
	// it is for, and this one exists on every Windows machine, so the check
	// does not depend on wuserbox having been run here before.
	const readers = "Users"
	account, err := sid.Lookup(readers)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := acl.Protect(dir); err != nil {
		t.Fatal(err)
	}
	if acl.Reads(dir, account.String()) {
		t.Fatalf("%s could read %s before anything was granted, so this proves nothing", readers, dir)
	}
	if err := ensureReadable(readers, dir); err != nil {
		t.Fatal(err)
	}
	if !acl.Reads(dir, account.String()) {
		t.Errorf("%s still cannot read %s", readers, dir)
	}
	// Asked again it changes nothing and still says yes, which is what makes it
	// safe to call on every run.
	if err := ensureReadable(readers, dir); err != nil {
		t.Fatal(err)
	}
	if !acl.Reads(dir, account.String()) {
		t.Errorf("asking twice took the permission away again")
	}
}

// TestEnsureReadableCreatesTheGroupWhenItIsMissing covers the branch that had
// never run anywhere: on a machine that has already used wuserbox the group
// exists, so nothing ever took the other path. A name nobody has is used
// instead, and deleted again.
func TestEnsureReadableCreatesTheGroupWhenItIsMissing(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("creating a local group needs administrator rights")
	}
	name := fmt.Sprintf("%stest-read-%d", group.Prefix, 100000+rand.Intn(800000))
	if _, err := sid.Lookup(name); err == nil {
		t.Skipf("%s already exists on this machine", name)
	}
	t.Cleanup(func() { _ = group.Delete(name) })

	dir := t.TempDir()
	if err := acl.Protect(dir); err != nil {
		t.Fatal(err)
	}
	if err := ensureReadable(name, dir); err != nil {
		t.Fatal(err)
	}
	account, err := sid.Lookup(name)
	if err != nil {
		t.Fatalf("the group was not created: %v", err)
	}
	// Creating the group is not the work; being able to read is. A run stopped
	// between the two would leave the group behind as proof of nothing, which
	// is why this asks about the directory rather than about the group.
	if !acl.Reads(dir, account.String()) {
		t.Errorf("%s was created but %s is still unreadable to it", name, dir)
	}
}
