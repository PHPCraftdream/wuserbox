package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// useCleanup is useProfile plus a cleanup section, for tests about the
// cleanup: list rather than the profile: one.
func useCleanup(t *testing.T, profile []string, cleanup []string) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	rules := &config.Config{Profile: config.Entries(profile), Cleanup: config.Masks(cleanup)}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

// TestCleanupClearsAMatchingFile checks glob 1 of the design: a glob names a
// file already sitting in the sandbox's own profile, and a fill takes it
// away. Fails without the cleanup wiring, since nothing else in Copy ever
// looks at rules.Cleanup.
func TestCleanupClearsAMatchingFile(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"**/*.log"})
	write(t, filepath.Join(dest, "agent.log"), "stale output")

	fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, "agent.log")); !os.IsNotExist(err) {
		t.Errorf("agent.log matched **/*.log and should have been cleared, stat error: %v", err)
	}
}

// TestCleanupClearsAMatchingDirectoryWhole checks glob 2: a glob names a
// directory, and the whole directory goes, not merely what happens to be
// directly in it.
func TestCleanupClearsAMatchingDirectoryWhole(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{".codex/sessions/**"})
	write(t, filepath.Join(dest, ".codex", "sessions", "one", "two.json"), "session data")

	fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, ".codex", "sessions")); !os.IsNotExist(err) {
		t.Errorf(".codex/sessions matched sessions/** and should have been removed whole, stat error: %v", err)
	}
}

// TestCleanupGlobThatMatchesNothingIsNotAnError checks glob 3: a cleanup
// section naming something that is not there costs nothing but a look, and
// must not fail the run or disturb what is there.
func TestCleanupGlobThatMatchesNothingIsNotAnError(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"nothing/here/**"})
	write(t, filepath.Join(dest, "keep.txt"), "still here")

	fill(t, dest)

	if got := read(t, filepath.Join(dest, "keep.txt")); got != "still here" {
		t.Errorf("an unrelated file was disturbed by a glob matching nothing: %q", got)
	}
}

// TestCleanupRunsBeforeTheCopy checks glob 4, and the ordering the design
// insists on: cleanup naming a path the profile section then copies must
// leave the freshly copied file in place, not a hole where cleanup ran last.
// If cleanup ran after the copy instead of before it, this file would end up
// missing.
func TestCleanupRunsBeforeTheCopy(t *testing.T) {
	home, dest := useCleanup(t, []string{".claude"}, []string{".claude/settings.json"})
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"fresh":true}`)
	write(t, filepath.Join(dest, ".claude", "settings.json"), `{"stale":true}`)

	fill(t, dest)

	if got := read(t, filepath.Join(dest, ".claude", "settings.json")); got != `{"fresh":true}` {
		t.Errorf("settings.json came back as %q, want the freshly copied file, not a hole cleanup left behind", got)
	}
}

// TestCleanupTouchesNothingOutsideItsGlobs checks glob 5: a file the sandbox
// wrote that no cleanup glob names must survive a fill untouched, the same
// guarantee TestCopyLeavesTheProfilesOwnBelongingsAlone gives the profile
// section.
func TestCleanupTouchesNothingOutsideItsGlobs(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"*.log"})
	write(t, filepath.Join(dest, "keep.json"), "the sandbox's own work")

	fill(t, dest)

	if got := read(t, filepath.Join(dest, "keep.json")); got != "the sandbox's own work" {
		t.Errorf("a file no glob named was disturbed: %q", got)
	}
}

// TestCleanupRefusesAGlobThatWouldMatchTheRegistryHive checks glob 6: NTUSER.DAT
// is the sandbox's HKEY_CURRENT_USER, and a glob broad enough to reach it must
// stop the whole run rather than clear everything else and skip that one name.
func TestCleanupRefusesAGlobThatWouldMatchTheRegistryHive(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"NTUSER*"})
	write(t, filepath.Join(dest, "NTUSER.DAT"), "the hive")
	write(t, filepath.Join(dest, "keep.txt"), "should not be reached either")

	_, _, err := Copy(dest, nil, nil)
	if err == nil {
		t.Fatal("a glob that would match NTUSER.DAT was accepted")
	}
	if exit.Of(err) != exit.BadConfig {
		t.Errorf("the refusal carried exit code %v, want %v (bad-config)", exit.Of(err), exit.BadConfig)
	}
	if _, err := os.Stat(filepath.Join(dest, "NTUSER.DAT")); err != nil {
		t.Errorf("the hive is gone even though the run was refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep.txt")); err != nil {
		t.Errorf("cleanup cleared other files before refusing the run entirely: %v", err)
	}
}

// TestCleanupRefusesADoubleStarOnItsOwn checks glob 7: ** on its own matches
// NTUSER.DAT as surely as a glob that names it, and has to be refused for the
// same reason -- not silently cleared around.
func TestCleanupRefusesADoubleStarOnItsOwn(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"**"})
	write(t, filepath.Join(dest, "NTUSER.DAT"), "the hive")

	_, _, err := Copy(dest, nil, nil)
	if err == nil {
		t.Fatal("cleanup: [**] was accepted")
	}
	if _, err := os.Stat(filepath.Join(dest, "NTUSER.DAT")); err != nil {
		t.Errorf("the hive is gone even though the run was refused: %v", err)
	}
}

// TestEmptyCleanupChangesNothingAndCostsNoWalk checks glob 8, both halves.
// "Changes nothing" is shown against real files, filled through Copy.
// "Costs no walk" needs a sharper probe than watching files stay put: an
// inert walk over zero globs would leave every file alone too, so it would
// not tell the two apart. A nil *os.Root does: any attempt to use it panics,
// so calling clearCleanup with nil and an empty list only returns cleanly if
// the empty list is answered before root is ever touched.
func TestEmptyCleanupChangesNothingAndCostsNoWalk(t *testing.T) {
	_, dest := useCleanup(t, nil, nil)
	write(t, filepath.Join(dest, "keep.txt"), "untouched")

	fill(t, dest)

	if got := read(t, filepath.Join(dest, "keep.txt")); got != "untouched" {
		t.Errorf("keep.txt came back as %q with no cleanup globs at all", got)
	}

	removed, err := clearCleanup(nil, nil)
	if err != nil {
		t.Fatalf("an empty cleanup list returned an error instead of skipping the walk: %v", err)
	}
	if removed != nil {
		t.Errorf("an empty cleanup list reported removing %v", removed)
	}
}

// TestCleanupRefusesAGlobBroadEnoughToReachUsrClassDat checks that the same
// refusal NTUSER.DAT gets reaches UsrClass.dat too: "AppData/**" names none
// of NTUSER.DAT's own family (that hive sits at the profile root, not under
// AppData) and would still take the per-user class registration hive the
// profile service built at AppData\Local\Microsoft\Windows\UsrClass.dat.
// Fails without the fix, since refuseReservedCleanup only ever looked at
// NTUSER.DAT's family.
func TestCleanupRefusesAGlobBroadEnoughToReachUsrClassDat(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"AppData/**"})
	hive := filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
	write(t, hive, "classes")
	write(t, filepath.Join(dest, "keep.txt"), "should not be reached either")

	_, _, err := Copy(dest, nil, nil)
	if err == nil {
		t.Fatal("a glob that would match UsrClass.dat was accepted")
	}
	if exit.Of(err) != exit.BadConfig {
		t.Errorf("the refusal carried exit code %v, want %v (bad-config)", exit.Of(err), exit.BadConfig)
	}
	if _, err := os.Stat(hive); err != nil {
		t.Errorf("the hive is gone even though the run was refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep.txt")); err != nil {
		t.Errorf("cleanup cleared other files before refusing the run entirely: %v", err)
	}
}

// TestCleanupStillClearsTheSandboxesOwnTemp checks that guarding UsrClass.dat
// does not cost the feature its commonest case: Temp is the sandbox's own
// scratch directory, nowhere near AppData\Local\Microsoft\Windows, and a
// glob naming it must still run rather than being caught by a guard drawn
// too wide around the profile service's own files.
func TestCleanupStillClearsTheSandboxesOwnTemp(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"Temp/**"})
	write(t, filepath.Join(dest, "Temp", "scratch.tmp"), "work in progress")

	fill(t, dest)

	if _, err := os.Stat(filepath.Join(dest, "Temp", "scratch.tmp")); !os.IsNotExist(err) {
		t.Errorf("Temp/** should have cleared the sandbox's own scratch file, stat error: %v", err)
	}
}

// TestCleanupCannotReachOutOfTheProfileThroughAJunction checks glob 9,
// following the shape of TestCopyCannotBeWalkedOutOfTheProfileThroughAJunction.
// The glob is a name-only mask with no separator, "*.txt" -- it does not match
// "linked" itself, so clearing it can only happen by the walk descending into
// the junction and finding something inside that matches. If it followed the
// link, it would find "precious.txt" on the far side and take it, which is
// exactly the escape the root exists to make impossible.
func TestCleanupCannotReachOutOfTheProfileThroughAJunction(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"*.txt"})
	if err := os.MkdirAll(filepath.Join(dest, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()
	precious := filepath.Join(outside, "precious.txt")
	write(t, precious, "do not touch")

	link := filepath.Join(dest, "linked")
	if err := os.RemoveAll(link); err != nil {
		t.Fatal(err)
	}
	junctionTo(t, link, outside)

	fill(t, dest)

	if _, err := os.Stat(precious); err != nil {
		t.Errorf("a file outside the profile was deleted through the junction: %v", err)
	}
}

// TestCleanupRefusesAGlobNamingADirectoryTheHiveSitsUnder checks the shape
// that used to slip past both reserved lists: a glob with no separator is
// tested against the last segment of a path, so "AppData" never matches
// AppData\Local\Microsoft\Windows\UsrClass.dat -- it ends in UsrClass.dat --
// and yet the cleanup walk removes the AppData directory whole, hive and
// all, with Copy reporting success. Naming an ancestor of a reserved path
// is asking for something that cannot be granted, the same way naming the
// path itself is, and gets the same refusal instead of a quiet clearing
// around it.
func TestCleanupRefusesAGlobNamingADirectoryTheHiveSitsUnder(t *testing.T) {
	for _, glob := range []string{"AppData", "AppData/Local"} {
		t.Run(glob, func(t *testing.T) {
			_, dest := useCleanup(t, nil, []string{glob})
			hive := filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
			write(t, hive, "classes")
			write(t, filepath.Join(dest, "keep.txt"), "should not be reached either")

			_, _, err := Copy(dest, nil, nil)
			if err == nil {
				t.Fatal("a glob naming a directory the hive sits under was accepted")
			}
			if exit.Of(err) != exit.BadConfig {
				t.Errorf("the refusal carried exit code %v, want %v (bad-config)", exit.Of(err), exit.BadConfig)
			}
			if _, err := os.Stat(hive); err != nil {
				t.Errorf("the hive is gone even though the run was refused: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dest, "keep.txt")); err != nil {
				t.Errorf("cleanup cleared other files before refusing the run entirely: %v", err)
			}
		})
	}
}

// TestCleanupRefusesEveryGlobTheFamilyRuleBringsIn asks the refusal
// question directly, first for globs it refused before the families were
// the description -- the refusal must be a superset of itself, never a
// churn -- and then for globs that reach only what the families add: the
// TxR set no table ever listed, the container whose counter has moved
// past 01, a .TM.blf under another machine's GUID. Fails without the fix:
// the tables answered for one example of each family, and these globs
// miss every example while matching real members a real profile holds.
func TestCleanupRefusesEveryGlobTheFamilyRuleBringsIn(t *testing.T) {
	for _, glob := range []string{
		"NTUSER.DAT",
		"NTUSER*",
		"ntuser.ini",
		"NTUSER.DAT.LOG1",
		"NTUSER.DAT{a0876e4c-1cb1-11d9-9669-0800200c9a66}.TM.blf",
		"NTUSER.DAT{a0876e4c-1cb1-11d9-9669-0800200c9a66}.TMContainer00000000000000000001.regtrans-ms",
		"UsrClass.dat",
		"UsrClass.dat.LOG2",
		"AppData/Local/Microsoft/Windows/UsrClass.dat",
		"*.blf",
		"*.regtrans-ms",
		"**",
		"AppData/**",
		"AppData",
		"AppData/Local",
		"Windows",
		"*.TxR.*",
		"NTUSER.DAT{*}.TxR.0.regtrans-ms",
		"UsrClass.dat{5038ca3b-376d-11e1-99a6-000c2905161f}.TMContainer00000000000000000002.regtrans-ms",
		"NTUSER.DAT{6*.TM.blf",
		"AppData/Local/Microsoft/Windows/UsrClass.dat{*}.TxR.1.regtrans-ms",
	} {
		if err := CleanupNamesSomethingReserved(config.Masks([]string{glob})); err == nil {
			t.Errorf("cleanup glob %q was accepted, and the walk would have taken what it reaches", glob)
		}
	}
}

// TestCleanupStillAcceptsGlobsNamingWhatIsNotTheProfileServices pins the
// rule's outside edge. Temp is the sandbox's own scratch and Roaming is
// account.MakeProfile's own doing -- no glob naming either may start
// being refused because the registry families next door grew a
// description. The names at the bottom are ones Windows does not write --
// a non-hexadecimal GUID, a third transaction log, a container counter
// without its padding, an editor's .old -- and a guard drawn exactly to
// the family leaves them alone too.
func TestCleanupStillAcceptsGlobsNamingWhatIsNotTheProfileServices(t *testing.T) {
	for _, glob := range []string{
		"AppData/Local/Temp/**",
		"Temp",
		"AppData/Local/Temp",
		"AppData/Local/Roaming/**",
		"Roaming/**",
		"*.log",
		"NTUSER.DAT{g*}",
		"UsrClass.dat.LOG3",
		"UsrClass.dat{a0876e4c-1cb1-11d9-9669-0800200c9a66}.TMContainer1.regtrans-ms",
		"*.old",
	} {
		if err := CleanupNamesSomethingReserved(config.Masks([]string{glob})); err != nil {
			t.Errorf("cleanup glob %q was refused: %v -- the guard reached past the profile service's own files", glob, err)
		}
	}
}

// TestCleanupRefusesAGlobReachingAFamilyMemberTheTablesNeverListed runs
// the refusal end to end with a glob the old tables had no reason to
// refuse: the container whose counter has moved on to 02 sits beside the
// hive in every real profile, and a glob naming it was accepted -- and
// the walk took it. Fails without the fix.
func TestCleanupRefusesAGlobReachingAFamilyMemberTheTablesNeverListed(t *testing.T) {
	_, dest := useCleanup(t, nil, []string{"UsrClass.dat{*}.TMContainer00000000000000000002.regtrans-ms"})
	member := filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows",
		"UsrClass.dat{5038ca3b-376d-11e1-99a6-000c2905161f}.TMContainer00000000000000000002.regtrans-ms")
	write(t, member, "windows' work")
	write(t, filepath.Join(dest, "keep.txt"), "should not be reached either")

	_, _, err := Copy(dest, nil, nil)
	if err == nil {
		t.Fatal("a glob reaching a transaction container was accepted")
	}
	if exit.Of(err) != exit.BadConfig {
		t.Errorf("the refusal carried exit code %v, want %v (bad-config)", exit.Of(err), exit.BadConfig)
	}
	if _, err := os.Stat(member); err != nil {
		t.Errorf("the container is gone even though the run was refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep.txt")); err != nil {
		t.Errorf("cleanup cleared other files before refusing the run entirely: %v", err)
	}
}

// TestCleanupRefusesAGlobSpelledTheWayTheVolumeReadsIt extends the glob
// question to the spellings the volume improves on. The question is asked of
// the glob as written first -- the check that has always run -- and then of
// its volume-read spellings: the padded-stripped one, each segment losing
// the trailing dots and spaces Win32 strips before it opens or creates
// anything, and the de-aliased one, where an 8.3-shaped segment's
// tilde-and-digits becomes the star the truncation really stands for
// ("NTUSER~1.DAT" asking, in truth, for "NTUSER*.DAT"). A glob is refused
// when one of the normalized spellings reaches a reserved family, and the
// message still names the pattern as written -- that is the line the person
// reading the rules file can find. The refusal has to arrive through a real
// Copy, before clearCleanup's walk has removed anything, so the hive and a
// planted member of its family sit beside the glob and must still hold
// their content when the run comes back refused.
func TestCleanupRefusesAGlobSpelledTheWayTheVolumeReadsIt(t *testing.T) {
	for _, glob := range []string{"NTUSER.DAT.", "NTUSER.DAT ", "NTUSER~1.DAT", "UsrClass.dat."} {
		t.Run(glob, func(t *testing.T) {
			_, dest := useCleanup(t, nil, []string{glob})
			hive := filepath.Join(dest, "NTUSER.DAT")
			members := plantNTUSERFamily(t, dest)
			if glob == "UsrClass.dat." {
				hive = hivePath(t, dest)
				members = plantUsrClassFamily(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows"))
			}
			write(t, hive, profileServiceHive)

			_, _, err := Copy(dest, nil, nil)
			if err == nil {
				t.Fatalf("cleanup glob %q was accepted, and the volume would open it onto the hive's name", glob)
			}
			if !strings.Contains(err.Error(), glob) {
				t.Errorf("the refusal did not name the glob as written, %q: %v", glob, err)
			}
			if exit.Of(err) != exit.BadConfig {
				t.Errorf("the refusal carried exit code %v, want %v (bad-config)", exit.Of(err), exit.BadConfig)
			}
			if got := read(t, hive); got != profileServiceHive {
				t.Errorf("the hive was disturbed before the run was refused over %q: it now holds %q", glob, got)
			}
			for _, m := range members {
				if got := read(t, m); got != "windows' work" {
					t.Errorf("%s was taken before the run was refused over %q: it now holds %q", m, glob, got)
				}
			}
		})
	}
}
