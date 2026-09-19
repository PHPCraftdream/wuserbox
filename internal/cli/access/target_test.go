// Tests for the directory a command is aimed at: how it is spelled, which
// commands read the read-only switch, and the agreement between the flags
// these commands register and the flags their help documents. The helper
// shared with the file beside this one lives here.

package access

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// TestMain loads the rules parser before any test moves LOCALAPPDATA. The
// parser caches a native library under that directory and keeps it open, which
// would otherwise leave a temporary directory undeletable.
func TestMain(m *testing.M) {
	warm, err := os.CreateTemp("", "wuserbox-warm-*.ktav")
	if err == nil {
		_, _ = warm.WriteString("projects: [\n]\n")
		warm.Close()
		os.Setenv(config.EnvPath, warm.Name())
		_, _ = config.Load()
		os.Remove(warm.Name())
		os.Unsetenv(config.EnvPath)
	}
	os.Exit(m.Run())
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

func TestParseTargetResolvesAnyPathSpelling(t *testing.T) {
	dir := tempDir(t)
	project := tempDir(t)
	drive := strings.ToLower(dir[:1])
	shellStyle := "/" + drive + filepath.ToSlash(dir[2:])

	for _, spelling := range []string{dir, filepath.ToSlash(dir), shellStyle, `"` + dir + `"`} {
		got, err := parseTarget("grant", []string{spelling, "--dir", project})
		if err != nil {
			t.Errorf("%s: %v", spelling, err)
			continue
		}
		if !strings.EqualFold(got.path, dir) {
			t.Errorf("%s resolved to %q, want %q", spelling, got.path, dir)
		}
		if got.kind != grant.RW {
			t.Errorf("%s: kind is %q, want %q", spelling, got.kind, grant.RW)
		}
	}
}

func TestParseTargetReadsTheReadOnlySwitch(t *testing.T) {
	got, err := parseTarget("grant", []string{tempDir(t), "--ro", "--dir", tempDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	if got.kind != grant.RO {
		t.Errorf("kind is %q", got.kind)
	}
}

func TestParseTargetNeedsExactlyOneDirectory(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		if _, err := parseTarget("grant", args); err == nil {
			t.Errorf("%v should have been rejected", args)
		}
	}
}

// TestTargetArgumentsRoundTrip is also the regression guard for a rebuilt
// command line that named the command but not as one: without the dash,
// Elevate's re-exec would read "grant" as a program to run rather than as the
// grant command.
func TestTargetArgumentsRoundTrip(t *testing.T) {
	original := target{path: `C:\tools`, project: `C:\project`, kind: grant.RO}
	args := original.args("grant")
	if args[0] != "--grant" {
		t.Fatalf("rebuilt arguments start with %q, want \"--grant\"", args[0])
	}
	rebuilt, err := parseTarget("grant", args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.kind != original.kind {
		t.Errorf("kind changed to %q", rebuilt.kind)
	}
	if !strings.EqualFold(rebuilt.path, original.path) {
		t.Errorf("path changed to %q", rebuilt.path)
	}
}

func TestLoadReportsAnUninitializedSandbox(t *testing.T) {
	t.Setenv("LOCALAPPDATA", tempDir(t))
	_, err := load(tempDir(t))
	if err == nil || !strings.Contains(err.Error(), "wuserbox --init") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestTheShapeOfTheAnswerTravelsWithTheArguments is the regression guard for a
// command line rebuilt without --json. add-dir hands the directory over by
// calling grant, and grant then wrote prose where the caller had asked for one
// JSON document; remove-dir lost it the same way when it called revoke.
func TestTheShapeOfTheAnswerTravelsWithTheArguments(t *testing.T) {
	asked := target{path: `C:\tools`, project: `C:\project`, kind: grant.RO, asJSON: true}
	for _, command := range []string{"grant", "revoke"} {
		rebuilt := asked.args(command)
		var carriesJSON bool
		for _, arg := range rebuilt {
			if arg == "--json" {
				carriesJSON = true
			}
		}
		if !carriesJSON {
			t.Errorf("%v does not carry --json", rebuilt)
		}
		// And what it carries has to parse back into the same request.
		back, err := parseTarget(command, rebuilt[1:])
		if err != nil {
			t.Fatalf("%v does not parse back: %v", rebuilt, err)
		}
		if !back.asJSON {
			t.Errorf("the request came back as %+v", back)
		}
		// The kind only travels where the command reads it. Taking a directory
		// back has no read-only half, and rebuilding the line with --ro would
		// now be rejected by the very command the elevated attempt re-runs.
		if readOnlyApplies(command) && back.kind != asked.kind {
			t.Errorf("the kind came back as %q, want %q", back.kind, asked.kind)
		}
	}

	// Without the flag it must not appear from nowhere.
	plain := target{path: `C:\tools`, project: `C:\project`, kind: grant.RW}
	for _, arg := range plain.args("grant") {
		if arg == "--json" {
			t.Error("a plain request was rebuilt as a JSON one")
		}
	}
}

// TestTheHelpListsExactlyTheFlagsTheseCommandsTake holds the manual to what the
// commands really are. The options in the help are written by hand, so nothing
// else stops one from drifting: --ro was registered on all four of these and
// read by two, which made "wuserbox --revoke <dir> --ro" a flag that looked as
// though it narrowed what was taken back and did nothing at all.
func TestTheHelpListsExactlyTheFlagsTheseCommandsTake(t *testing.T) {
	for _, command := range []string{"grant", "revoke", "add-dir", "remove-dir"} {
		flags, _ := targetFlags(command)
		undocumented, missing := usage.Mismatch(command, flags)
		if len(undocumented) > 0 {
			t.Errorf("%s takes %v, which its help never mentions", command, undocumented)
		}
		if len(missing) > 0 {
			t.Errorf("the help offers %v on %s, which it would reject", missing, command)
		}
	}
}

// TestTakingADirectoryBackHasNoReadOnlyHalf is the regression guard for a flag
// that was accepted and ignored. Revoking and forgetting a directory take the
// whole of it back; --ro on either used to parse, change nothing, and report
// success, so a command line that read as though it narrowed what was withdrawn
// withdrew everything.
func TestTakingADirectoryBackHasNoReadOnlyHalf(t *testing.T) {
	for _, command := range []string{"revoke", "remove-dir"} {
		if _, err := parseTarget(command, []string{tempDir(t), "--ro"}); err == nil {
			t.Errorf("wuserbox --%s <dir> --ro was accepted", command)
		}
	}
	// And it still means something where it does.
	for _, command := range []string{"grant", "add-dir"} {
		got, err := parseTarget(command, []string{tempDir(t), "--ro"})
		if err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		if got.kind != grant.RO {
			t.Errorf("%s read --ro as %q", command, got.kind)
		}
	}
}

// TestOnlyAnAccessDeniedFromTheACLLayerIsWorthAnElevatedSecondAttempt holds
// the escalation to what elevation fixes. Every failure used to ask for
// administrator rights: a typo'd path, a damaged record or a tree refused
// for a hard link all ended in the same consent dialog, which is how an
// operator learns to approve it without reading it.
func TestOnlyAnAccessDeniedFromTheACLLayerIsWorthAnElevatedSecondAttempt(t *testing.T) {
	if !elevationCanFix(fmt.Errorf("changing the permissions of %s: %w", `C:\tools`, acl.ErrAccessDenied)) {
		t.Error("the one failure more rights can fix did not ask for them")
	}
	for _, cause := range []error{
		fmt.Errorf("open C:\\nope: no such file or directory"),
		exit.Errorf(exit.NotFound, "no sandbox for C:\\project yet; run `wuserbox --init` there"),
		fmt.Errorf("C:\\linked is also named C:\\elsewhere, which is outside C:\\linked"),
	} {
		if elevationCanFix(cause) {
			t.Errorf("%v asked for a consent dialog, and elevation cannot fix it", cause)
		}
	}
}

// TestNothingPastASeparatorIsDroppedSilently is the regression guard for a
// command line whose tail vanished: the flag package stops at a bare "--",
// nothing here read what it kept there, and "--grant <dir> -- --ro" handed
// the directory over writable.
func TestNothingPastASeparatorIsDroppedSilently(t *testing.T) {
	for _, args := range [][]string{
		{tempDir(t), "--", "--ro"},
		{tempDir(t), "--", "--dry-run"},
	} {
		if _, err := parseTarget("grant", args); err == nil {
			t.Errorf("%v was accepted; whatever came after \"--\" would have been dropped", args)
		}
	}
	// A bare "--" with nothing after it drops nothing, and stays welcome.
	got, err := parseTarget("grant", []string{tempDir(t), "--"})
	if err != nil {
		t.Fatalf("a bare \"--\" with nothing after it: %v", err)
	}
	if got.kind != grant.RW {
		t.Errorf("kind is %q", got.kind)
	}
}
