package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// TestArgsCarriesTheDashThatMarksACommand is the regression guard for a
// rebuilt command line that named the command but not as one. Elevate re-runs
// wuserbox with these arguments as a brand new process, and a first word
// without a dash is read as a program to run, not as init: the elevated copy
// would have gone looking for a program called "init" instead of building the
// sandbox.
func TestArgsCarriesTheDashThatMarksACommand(t *testing.T) {
	args := Options{Dir: `C:\project`, RW: []string{`C:\extra`}, NoAI: true, AllowLinks: true}.Args()
	if len(args) == 0 || args[0] != "--init" {
		t.Fatalf("the command line starts with %q, want \"--init\"", args)
	}
	if !strings.Contains(strings.Join(args, " "), `--dir C:\project`) {
		t.Errorf("the project directory is missing: %v", args)
	}
	if !strings.Contains(strings.Join(args, " "), `--allow-links`) {
		t.Errorf("the link policy is missing from the elevated command line: %v", args)
	}
}

func TestAccountCollisionRefusesReplacementOfAnotherSandbox(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("account collision fixture needs administrator rights")
	}
	tag := strconv.FormatInt(time.Now().UnixNano(), 16)
	firstGroup := fmt.Sprintf("%sidentity-a-%s-deadbeef", group.Prefix, tag)
	secondGroup := fmt.Sprintf("%sidentity-b-%s-deadbeef", group.Prefix, tag)
	firstDir := filepath.Join(t.TempDir(), "first")
	secondDir := filepath.Join(t.TempDir(), "second")
	if err := os.Mkdir(firstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(secondDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := group.Add(firstGroup, firstDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(firstGroup) })
	if err := group.Add(secondGroup, secondDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Delete(secondGroup) })

	legacyAccount := acct.LegacyNameFor(firstGroup)
	password, err := acct.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := acct.Add(legacyAccount, firstDir, password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acct.Delete(legacyAccount) })
	if err := acct.EnsureMembership(legacyAccount, firstGroup); err != nil {
		t.Fatal(err)
	}

	s := &state.State{}
	if _, err := accountName(s, secondGroup, secondDir); err == nil {
		t.Fatal("colliding account was accepted for the second sandbox")
	}
	if _, err := sid.Lookup(legacyAccount); err != nil {
		t.Fatalf("collision guard lost the first sandbox account: %v", err)
	}
}
