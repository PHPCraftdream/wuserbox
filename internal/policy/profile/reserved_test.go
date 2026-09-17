package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// The stand-ins these tests plant are text files at the reserved paths --
// never real registry hives, which the tests have no business building or
// opening. What each one pins is that the package must never copy over or
// remove the file at that path, whatever door the code reaches it through.
const profileServiceHive = "the profile service built this"
const userHive = "the user's own class hive"

func hivePath(t *testing.T, base string) string {
	t.Helper()
	return filepath.Join(base, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
}

// TestAMirrorSparesTheClassHiveAnIncludeListNeverNamed pins the mirroring's
// stray removal. The include list leaves UsrClass.dat off the present list
// the walk builds, so removeStrayChildren reads the hive the profile service
// built as a stray and RemoveAll takes it -- the reviewer's reproduction,
// measured: the sandbox's class hive was destroyed on an ordinary run. The
// .old file and notes.txt sit beside it to show the fix must spare the
// reserved family specifically -- .LOG1 travels with the hive, .old and
// notes.txt do not -- and that the mirroring itself keeps working.
func TestAMirrorSparesTheClassHiveAnIncludeListNeverNamed(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: "AppData", Include: config.Masks([]string{"Roaming/**"})}})
	// The source holds the Windows directory so the walk descends into the
	// destination's -- the mirroring only clears strays where the walk goes.
	write(t, filepath.Join(home, "AppData", "Roaming", "settings.dat"), "roaming")
	write(t, filepath.Join(home, "AppData", "Local", "Microsoft", "Windows", "keep.txt"), "kept")

	write(t, hivePath(t, dest), profileServiceHive)
	write(t, hivePath(t, dest)+".LOG1", "companion")
	write(t, hivePath(t, dest)+".old", "not the family")
	write(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "notes.txt"), "a stray nothing reserves")

	fill(t, dest)
	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the mirroring destroyed the sandbox's class hive: it now holds %q", got)
	}
	if got := read(t, hivePath(t, dest)+".LOG1"); got != "companion" {
		t.Errorf("the mirroring destroyed the hive's transaction log companion: it now holds %q", got)
	}
	if _, err := os.Stat(hivePath(t, dest) + ".old"); !os.IsNotExist(err) {
		t.Errorf("a file merely named like the hive's family survived the mirroring: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "notes.txt")); !os.IsNotExist(err) {
		t.Errorf("a plain stray the reserved names do not reach survived the mirroring: %v", err)
	}
	if got := read(t, filepath.Join(dest, "AppData", "Roaming", "settings.dat")); got != "roaming" {
		t.Errorf("the mirroring stopped working where the guard did not apply: %q", got)
	}
}

// TestATakeBackWhoseLimitsReachTheHiveSparesIt pins the take-back that goes
// through clearKeeping. An entry carrying limits routes forget through the
// walk, and the walk never had UsrClass.dat on its present list -- it is not
// in the source -- so the take-back read the hive the profile service built
// as the entry's own and removed it. Whatever the route, the answer has to
// be the same: the hive is nobody's copy to take back.
func TestATakeBackWhoseLimitsReachTheHiveSparesIt(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: "AppData", Depth: depthPtr(5)}})
	write(t, filepath.Join(home, "AppData", "keep.txt"), "ours")
	fill(t, dest)

	write(t, hivePath(t, dest), profileServiceHive)
	if err := (&config.Config{Profile: config.Entries([]string{})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the take-back destroyed the sandbox's class hive: it now holds %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "AppData", "keep.txt")); !os.IsNotExist(err) {
		t.Errorf("the entry left the list but its copy is still there: %v", err)
	}
}

// TestATakeBackOfABareEntrySparesTheHiveUnderIt pins the bare entry's route
// out, clearEntry's RemoveAll. A bare entry reaches the plain RemoveAll at
// the bottom of clearEntry, which takes the directory whole -- AppData and
// everything the profile service built under it, class hive included. The
// hive sits inside a directory the rules file named, but naming AppData was
// a statement about copying, not a license to remove Windows' own work.
func TestATakeBackOfABareEntrySparesTheHiveUnderIt(t *testing.T) {
	home, dest := useProfile(t, []string{"AppData"})
	write(t, filepath.Join(home, "AppData", "keep.txt"), "ours")
	fill(t, dest)

	write(t, hivePath(t, dest), profileServiceHive)
	if err := (&config.Config{Profile: config.Entries([]string{})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the bare-entry take-back destroyed the sandbox's class hive: it now holds %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "AppData", "keep.txt")); !os.IsNotExist(err) {
		t.Errorf("the entry left the list but its copy is still there: %v", err)
	}
}

// TestATakeBackSparesTheRegistryHiveAtTheProfileRoot pins the same promise
// at the profile root, where the hive family's names are bare. A record
// naming NTUSER.DAT outright -- the entry list is the take-back's whole
// authority -- must be spared by it, not RemoveAll'd: reservedProfileNames
// are bare names because the hive and its companions all sit at the root,
// and the take-back has to answer to the same table.
func TestATakeBackSparesTheRegistryHiveAtTheProfileRoot(t *testing.T) {
	_, dest := useProfile(t, []string{})
	write(t, filepath.Join(dest, "NTUSER.DAT"), "the sandbox's own registry")
	write(t, filepath.Join(dest, "NTUSER.DAT.LOG1"), "its transaction log")

	if err := Clear(dest, []config.Entry{{Path: "NTUSER.DAT"}, {Path: "NTUSER.DAT.LOG1"}}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dest, "NTUSER.DAT")); got != "the sandbox's own registry" {
		t.Errorf("the take-back destroyed the sandbox's own registry hive: it now holds %q", got)
	}
	if got := read(t, filepath.Join(dest, "NTUSER.DAT.LOG1")); got != "its transaction log" {
		t.Errorf("the take-back destroyed the hive's transaction log: it now holds %q", got)
	}
}

// TestACopyDoesNotLayTheUsersClassHiveOverTheSandboxes pins the copy itself.
// An entry over AppData with no include list walks the user's real AppData,
// whose UsrClass.dat is the USER's own class hive -- the stand-in planted in
// the source here. Unfixed, the copy lays that file over the empty one the
// profile service built the sandbox, handing the sandbox the user's hive:
// their class registrations, inside a machine the sandbox was meant to keep
// separate. Copying is as much a way of destroying the hive as deleting --
// it overwrites it with the wrong one.
func TestACopyDoesNotLayTheUsersClassHiveOverTheSandboxes(t *testing.T) {
	home, dest := useProfile(t, []string{"AppData"})
	write(t, filepath.Join(home, "AppData", "keep.txt"), "ours")
	write(t, hivePath(t, home), userHive)
	write(t, hivePath(t, dest), profileServiceHive)

	fill(t, dest)
	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the copy laid the user's class hive over the sandbox's: it now holds %q", got)
	}
	if got := read(t, filepath.Join(dest, "AppData", "keep.txt")); got != "ours" {
		t.Errorf("the copy itself stopped working where the guard did not apply: %q", got)
	}
}

// TestTheGuardSparesTheHiveUnderAnyCapitals pins how the guard compares
// names. The reserved tables are spelled one way -- UsrClass.dat -- and the
// file system answers for any of them: on this machine's NTFS the profile
// service's hive can sit there as usrclass.dat just as well, and a guard
// comparing by bytes reads the hive's own name as a stranger's and destroys
// it through the very hole it exists to close. The comparison has to go
// through the same fold the package compares names by.
func TestTheGuardSparesTheHiveUnderAnyCapitals(t *testing.T) {
	home, dest := useProfile(t, []string{"AppData"})
	write(t, filepath.Join(home, "AppData", "Local", "Microsoft", "Windows", "keep.txt"), "kept")
	write(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "usrclass.dat"), profileServiceHive)

	fill(t, dest)
	if got := read(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "usrclass.dat")); got != profileServiceHive {
		t.Errorf("the guard did not recognize the hive under other capitals: the file now holds %q", got)
	}
	if got := read(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "keep.txt")); got != "kept" {
		t.Errorf("the copy itself stopped working where the guard did not apply: %q", got)
	}
}

// TestAFileThatMerelySharesAReservedNameIsStillOurs pins the guard's
// narrowness. The root-name table matches at the profile root only -- the
// hive family sits there and nowhere else -- so a file called NTUSER.DAT
// under tools/ is nobody's registry: it is a file the rules file named, and
// a guard that spared it by bare name wherever it sits would let any
// directory hide behind the hive's name.
func TestAFileThatMerelySharesAReservedNameIsStillOurs(t *testing.T) {
	home, dest := useProfile(t, []string{"tools"})
	write(t, filepath.Join(home, "tools", "NTUSER.DAT"), "just a file an agent needs")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, "tools", "NTUSER.DAT")); got != "just a file an agent needs" {
		t.Errorf("a file sharing a reserved name away from the profile root was not copied: %q", got)
	}
}

// TestATakeBackOfAReservedPathCarriedWithLimitsSparesIt closes the last
// door: clearEntry's bare branch spares a reserved path, but a record may
// name the hive carrying limits -- an early build's rules file could have
// written exclude masks onto it -- and the non-bare branch takes a target
// that is not a directory straight to RemoveAll, honoring the name to the
// letter. The file the profile service built is not the record's to take.
func TestATakeBackOfAReservedPathCarriedWithLimitsSparesIt(t *testing.T) {
	_, dest := useProfile(t, []string{})
	hive := hivePath(t, dest)
	write(t, hive, profileServiceHive)

	entry := config.Entry{
		Path:    "AppData/Local/Microsoft/Windows/UsrClass.dat",
		Exclude: config.Masks([]string{"*.blf"}),
	}
	if err := Clear(dest, []config.Entry{entry}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, hive); got != profileServiceHive {
		t.Errorf("the class hive did not survive its own name on the record: %q", got)
	}
}

// TestAMirrorSparesTheHiveUnderADirectoryTheSourceHasLost is the stray
// question in its directory shape: the mirroring clears where the walk
// goes, and a source that has lost AppData/Local outright leaves the
// destination's a stray directory at the entry's first level -- the shape
// removeStrayChildren hands to the bottom RemoveAll whole. Whatever the
// hive sits under is the way to the hive, and the walk that clears around
// a spared file in the include-list shape clears around it here too.
func TestAMirrorSparesTheHiveUnderADirectoryTheSourceHasLost(t *testing.T) {
	home, dest := useProfile(t, []string{"AppData"})
	write(t, filepath.Join(home, "AppData", "keep.txt"), "ours")
	write(t, hivePath(t, dest), profileServiceHive)

	fill(t, dest)

	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the class hive went with the directory the source has lost: %q", got)
	}
	if got := read(t, filepath.Join(dest, "AppData", "keep.txt")); got != "ours" {
		t.Errorf("the mirror itself stopped happening: %q", got)
	}
}
