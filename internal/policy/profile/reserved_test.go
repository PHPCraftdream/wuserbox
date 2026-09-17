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

// The stand-in families spell their varying parts the way real profiles do
// -- GUIDs observed beside real hives, never the tables' one example --
// so the tests exercise the machine-to-machine variation the guard has to
// survive. The TxR files carry a GUID of their own, the way Windows
// builds them: the transaction manager's and TxR root's GUIDs differ even
// beside one hive.
const (
	usrClassOtherTMGUID  = "5038ca3b-376d-11e1-99a6-000c2905161f"
	usrClassOtherTxRGUID = "53b39e3d-18c4-11ea-a811-000d3aa4692b"
	ntuserOtherTMGUID    = "6cced2f1-6e01-11de-8bed-001e0bcd1824"
	ntuserOtherTxRGUID   = "77a2c7f1-26f0-11e5-80da-e41d2d741090"
)

// plantUsrClassFamily writes UsrClass.dat's whole transaction family into
// dir, every member under a name the reserved tables never listed: a
// .TM.blf under another machine's GUID, the container whose counter has
// moved on to 02, and the TxR set. Returns the members' paths so a test
// can assert each one's fate.
func plantUsrClassFamily(t *testing.T, dir string) []string {
	t.Helper()
	base := filepath.Join(dir, "UsrClass.dat")
	members := []string{
		base + "{" + usrClassOtherTMGUID + "}.TM.blf",
		base + "{" + usrClassOtherTMGUID + "}.TMContainer00000000000000000002.regtrans-ms",
		base + "{" + usrClassOtherTxRGUID + "}.TxR.blf",
		base + "{" + usrClassOtherTxRGUID + "}.TxR.0.regtrans-ms",
		base + "{" + usrClassOtherTxRGUID + "}.TxR.1.regtrans-ms",
	}
	for _, m := range members {
		write(t, m, "windows' work")
	}
	return members
}

// plantNTUSERFamily is plantUsrClassFamily for the hive at the profile
// root, whose family's names are bare.
func plantNTUSERFamily(t *testing.T, dir string) []string {
	t.Helper()
	base := filepath.Join(dir, "NTUSER.DAT")
	members := []string{
		base + "{" + ntuserOtherTMGUID + "}.TM.blf",
		base + "{" + ntuserOtherTMGUID + "}.TMContainer00000000000000000002.regtrans-ms",
		base + "{" + ntuserOtherTxRGUID + "}.TxR.blf",
		base + "{" + ntuserOtherTxRGUID + "}.TxR.0.regtrans-ms",
	}
	for _, m := range members {
		write(t, m, "windows' work")
	}
	return members
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

// TestAMirrorSparesTheHivesWholeFamily is the reproduced defect. The class
// hive itself survived the mirroring -- the guard from commit c72ded6 sees
// to that -- but the copy took every member of its family the tables had
// no exact name for: a .TM.blf carrying a different GUID, the container
// whose counter had moved on to 02, and the TxR set. Those names sit in a
// real Windows profile; each is Windows' work, and each came back as a
// stray the walk was happy to remove. The lookalikes at the bottom are
// names Windows does not write -- a non-hexadecimal GUID, a container
// counter without its padding, a transaction file with an editor's .old
// hung on it, a plain stray -- and must go on going.
func TestAMirrorSparesTheHivesWholeFamily(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: "AppData", Include: config.Masks([]string{"Roaming/**"})}})
	// The source holds the Windows directory so the walk descends into the
	// destination's -- the mirroring only clears strays where the walk goes.
	write(t, filepath.Join(home, "AppData", "Roaming", "settings.dat"), "roaming")
	write(t, filepath.Join(home, "AppData", "Local", "Microsoft", "Windows", "keep.txt"), "kept")

	win := filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows")
	write(t, hivePath(t, dest), profileServiceHive)
	write(t, hivePath(t, dest)+".LOG1", "companion")
	write(t, hivePath(t, dest)+".LOG2", "companion")
	members := plantUsrClassFamily(t, win)
	// One member under other capitals: the file system answers for them
	// all, and the family guard has to as well.
	lower := filepath.Join(win, "usrclass.dat{"+usrClassOtherTMGUID+"}.TMContainer00000000000000000002.regtrans-ms")
	write(t, lower, "windows' work")
	lookalikes := []string{
		filepath.Join(win, "UsrClass.dat{zzzzzzzz-1cb1-11d9-9669-0800200c9a66}.TM.blf"),
		filepath.Join(win, "UsrClass.dat{"+usrClassOtherTMGUID+"}.TMContainer1.regtrans-ms"),
		filepath.Join(win, "UsrClass.dat{"+usrClassOtherTMGUID+"}.TM.blf.old"),
		filepath.Join(win, "notes.txt"),
	}
	for _, l := range lookalikes {
		write(t, l, "not the family")
	}

	fill(t, dest)
	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the mirroring destroyed the sandbox's class hive: it now holds %q", got)
	}
	for _, m := range append(members, lower) {
		if got := read(t, m); got != "windows' work" {
			t.Errorf("the copy destroyed %s, a member of the hive's transaction family the tables never named: it now holds %q", m, got)
		}
	}
	for _, l := range lookalikes {
		if _, err := os.Stat(l); !os.IsNotExist(err) {
			t.Errorf("a lookalike the profile service never wrote survived the mirroring: %v", err)
		}
	}
	if got := read(t, filepath.Join(dest, "AppData", "Roaming", "settings.dat")); got != "roaming" {
		t.Errorf("the mirroring stopped working where the guard did not apply: %q", got)
	}
}

// TestATakeBackOfABareEntrySparesTheHivesFamilyUnderIt follows
// TestATakeBackOfABareEntrySparesTheHiveUnderIt one door over: the
// bare-entry take-back already spares the hive by routing around it, but
// the walk it routes through asks its per-child question of the same
// exact tables, and every family member the tables never named went with
// the clearing.
func TestATakeBackOfABareEntrySparesTheHivesFamilyUnderIt(t *testing.T) {
	home, dest := useProfile(t, []string{"AppData"})
	write(t, filepath.Join(home, "AppData", "keep.txt"), "ours")
	fill(t, dest)

	win := filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows")
	write(t, hivePath(t, dest), profileServiceHive)
	members := plantUsrClassFamily(t, win)

	if err := (&config.Config{Profile: config.Entries([]string{})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the bare-entry take-back destroyed the sandbox's class hive: it now holds %q", got)
	}
	for _, m := range members {
		if got := read(t, m); got != "windows' work" {
			t.Errorf("the bare-entry take-back destroyed %s, a member of the hive's transaction family: it now holds %q", m, got)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "AppData", "keep.txt")); !os.IsNotExist(err) {
		t.Errorf("the entry left the list but its copy is still there: %v", err)
	}
}

// TestATakeBackWhoseLimitsReachTheHiveSparesItsFamily follows
// TestATakeBackWhoseLimitsReachTheHiveSparesIt through clearKeeping's
// walk: the walk spares what its entry's limits would have copied, and it
// asked its reserved question of exact names, so a depth that reached the
// Windows directory swept the family around the one hive it spared.
func TestATakeBackWhoseLimitsReachTheHiveSparesItsFamily(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: "AppData", Depth: depthPtr(5)}})
	write(t, filepath.Join(home, "AppData", "keep.txt"), "ours")
	fill(t, dest)

	win := filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows")
	write(t, hivePath(t, dest), profileServiceHive)
	members := plantUsrClassFamily(t, win)

	if err := (&config.Config{Profile: config.Entries([]string{})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)

	if got := read(t, hivePath(t, dest)); got != profileServiceHive {
		t.Errorf("the take-back destroyed the sandbox's class hive: it now holds %q", got)
	}
	for _, m := range members {
		if got := read(t, m); got != "windows' work" {
			t.Errorf("the take-back's walk destroyed %s, a member of the hive's transaction family: it now holds %q", m, got)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "AppData", "keep.txt")); !os.IsNotExist(err) {
		t.Errorf("the entry left the list but its copy is still there: %v", err)
	}
}

// TestATakeBackSparesTheRegistryHivesFamilyAtTheProfileRoot follows
// TestATakeBackSparesTheRegistryHiveAtTheProfileRoot: a record naming a
// reserved path outright is the take-back's whole authority, and the root
// family's members are reserved paths -- a GUID the record's writer never
// saw, a counter past 01, a TxR segment, are still the sandbox's own
// registry. Both of clearEntry's routes are asked: the bare entry and one
// carrying limits.
func TestATakeBackSparesTheRegistryHivesFamilyAtTheProfileRoot(t *testing.T) {
	_, dest := useProfile(t, []string{})
	members := plantNTUSERFamily(t, dest)

	entries := []config.Entry{
		{Path: "NTUSER.DAT{" + ntuserOtherTMGUID + "}.TM.blf"},
		{Path: "NTUSER.DAT{" + ntuserOtherTMGUID + "}.TMContainer00000000000000000002.regtrans-ms",
			Exclude: config.Masks([]string{"*.blf"})},
		{Path: "NTUSER.DAT{" + ntuserOtherTxRGUID + "}.TxR.0.regtrans-ms"},
	}
	if err := Clear(dest, entries); err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if got := read(t, m); got != "windows' work" {
			t.Errorf("the take-back destroyed %s, a member of the root hive's transaction family its record named: it now holds %q", m, got)
		}
	}
}

// TestAFamilyNameAwayFromItsDirectoryIsStillOurs pins the family rule's
// locality, the way TestAFileThatMerelySharesAReservedNameIsStillOurs
// pins the root table's: NTUSER.DAT's transaction family lives at the
// profile root and UsrClass.dat's under AppData/Local/Microsoft/Windows,
// and a file carrying a family member's name anywhere else is nobody's
// registry -- it is a file the rules file named, and a guard that spared
// it by shape wherever it sits would let any directory hide behind the
// hive's family.
func TestAFamilyNameAwayFromItsDirectoryIsStillOurs(t *testing.T) {
	home, dest := useProfile(t, []string{"tools"})
	write(t, filepath.Join(home, "tools", "NTUSER.DAT{"+ntuserOtherTMGUID+"}.TM.blf"), "just a file an agent needs")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, "tools", "NTUSER.DAT{"+ntuserOtherTMGUID+"}.TM.blf")); got != "just a file an agent needs" {
		t.Errorf("a file carrying a family member's name away from the family's directory was not copied: %q", got)
	}
}
