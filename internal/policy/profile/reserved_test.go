package profile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

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

// TestACopyRefusesAnEntrySpelledTheWayTheVolumeImprovesOn pins the rules
// file's half of the spelling question. "NTUSER.DAT." and "NTUSER.DAT "
// open the file "NTUSER.DAT" keeps -- Win32 strips trailing dots and spaces
// per segment before it opens or creates anything, for reading and for
// writing alike, which is why the trailing-space plant below stores itself
// under the plain name -- and "NTUSER~1.DAT" is spelled the way Windows
// spells an 8.3 alias, which the volume resolves onto whatever long name it
// aliases. An entry carrying one of those spellings would land on a name
// the rules file never wrote, so what gets copied and what gets taken back
// would never agree about the name; within refuses it instead of quietly
// correcting it. The hives are planted at the PLAIN names, on both sides,
// so the refusal is the only thing standing between the odd spelling and
// the real file the volume would have found for it.
func TestACopyRefusesAnEntrySpelledTheWayTheVolumeImprovesOn(t *testing.T) {
	for _, spelling := range []string{
		"NTUSER.DAT.",
		"NTUSER.DAT ",
		"NTUSER~1.DAT",
		"AppData/Local/Microsoft/Windows/UsrClass.dat.",
	} {
		t.Run(spelling, func(t *testing.T) {
			home, dest := useProfile(t, []string{spelling})
			homeHive, destHive := filepath.Join(home, "NTUSER.DAT"), filepath.Join(dest, "NTUSER.DAT")
			if spelling == "AppData/Local/Microsoft/Windows/UsrClass.dat." {
				homeHive, destHive = hivePath(t, home), hivePath(t, dest)
			}
			write(t, homeHive, userHive)
			write(t, destHive, profileServiceHive)

			if _, _, err := Copy(dest, nil, nil); err == nil {
				t.Fatalf("the rules spelling %q was accepted, and the volume would have opened it onto a name the rules file never wrote", spelling)
			}
			if got := read(t, destHive); got != profileServiceHive {
				t.Errorf("the copy laid the user's hive over the sandbox's through the spelling %q: it now holds %q", spelling, got)
			}
			if got := read(t, homeHive); got != userHive {
				t.Errorf("the user's own hive was disturbed by the run spelled %q: it now holds %q", spelling, got)
			}
		})
	}
}

// TestATakeBackSparesTheHiveARecordSpelledTheWayTheVolumeReadsIt pins the
// record's half of the same question, where the answer is the opposite of
// the rules file's. A record is not a hand-edited file -- an earlier run of
// this tool wrote it -- so the spelling is not refused, it is asked of the
// volume: forget puts the resolved question ahead of withinRecorded, and a
// record spelling the hive with a trailing dot or a trailing space opens
// the hive the plain name keeps, measured through an os.Root, and is
// spared by the file it reaches. NTUSER~1.DAT needs no special answer: on
// a volume where the alias exists the resolved question spares it, and
// where the alias does not the name opens nothing and there is nothing to
// remove -- the hive survives either way. The root spellings are driven
// through a real Copy as well, because forget's spare runs inside one, on
// the way to the copy that rewrites the record.
func TestATakeBackSparesTheHiveARecordSpelledTheWayTheVolumeReadsIt(t *testing.T) {
	for _, spelling := range []string{
		"NTUSER.DAT.",
		"NTUSER.DAT ",
		"NTUSER~1.DAT",
		"AppData/Local/Microsoft/Windows/UsrClass.dat.",
	} {
		t.Run(spelling, func(t *testing.T) {
			_, dest := useProfile(t, []string{})
			hive := filepath.Join(dest, "NTUSER.DAT")
			atRoot := spelling != "AppData/Local/Microsoft/Windows/UsrClass.dat."
			if !atRoot {
				hive = hivePath(t, dest)
			}
			write(t, hive, profileServiceHive)

			if err := Clear(dest, []config.Entry{{Path: spelling}}); err != nil {
				t.Fatalf("the take-back refused a record spelling %q that an earlier run of this tool wrote: %v", spelling, err)
			}
			if got := read(t, hive); got != profileServiceHive {
				t.Errorf("the take-back honored the record's spelling %q to the letter: the hive now holds %q", spelling, got)
			}

			if !atRoot {
				return
			}
			if _, _, err := Copy(dest, []config.Entry{{Path: spelling}}, nil); err != nil {
				t.Fatalf("a fill refused to run over a record spelling %q: %v", spelling, err)
			}
			if got := read(t, hive); got != profileServiceHive {
				t.Errorf("the fill honored the record's spelling %q to the letter: the hive now holds %q", spelling, got)
			}
		})
	}
}

// shortNameSpelling asks Windows for the 8.3 spelling of an existing path,
// the way internal/win/acl's own tests do; empty where the volume answers
// nothing.
func shortNameSpelling(t *testing.T, path string) string {
	t.Helper()
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetShortPathNameW")
	written, _, _ := proc.Call(uintptr(unsafe.Pointer(wide)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if written == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer[:written])
}

// TestATakeBackSparesTheFamilyMemberAnAliasResolvesTo pins the resolution
// question on the one spelling this machine can build. A transaction file's
// name is far too long for 8.3, so the volume gives it an alias --
// NTUSER~1.BLF beside NTUSER.DAT{...}.TM.blf, measured -- and a record may
// carry the alias, the way any listing of the directory would spell it. The
// alias opens the member, so the resolved question spares the member by the
// name the volume answers with, whatever the record spelled. Skipped where
// 8.3 generation is switched off, the way junctionTo skips a machine that
// will not make a junction: there the alias opens nothing and the take-back
// simply has nothing to honor.
func TestATakeBackSparesTheFamilyMemberAnAliasResolvesTo(t *testing.T) {
	_, dest := useProfile(t, []string{})
	member := filepath.Join(dest, "NTUSER.DAT{"+familyExampleGUID+"}.TM.blf")
	const ours = "the member the record named by its alias"
	write(t, member, ours)

	alias := ""
	if short := shortNameSpelling(t, member); short != "" {
		alias = filepath.Base(short)
	}
	if alias == "" || alias == filepath.Base(member) {
		t.Skipf("this machine does not give %s an 8.3 alias (8.3 generation disabled): %q", filepath.Base(member), alias)
	}

	if err := Clear(dest, []config.Entry{{Path: alias}}); err != nil {
		t.Fatalf("the take-back refused the alias spelling %q a directory listing carries: %v", alias, err)
	}
	if got := read(t, member); got != ours {
		t.Errorf("the take-back took the family member through its alias %q: it now holds %q", alias, got)
	}
}

// TestATakeBackTakesAnAliasShapedNameThatResolvesOntoItself pins the
// resolved question's narrowness from the other side. notes~1.txt is spelled
// the way an alias is spelled, and the take-back asks the volume about it --
// but the only name it can resolve to is its own, and its own name is
// reserved under none, so the file is the record's to take. A guard that
// spared every suspicious spelling would let any directory hide behind an
// unlucky name.
func TestATakeBackTakesAnAliasShapedNameThatResolvesOntoItself(t *testing.T) {
	_, dest := useProfile(t, []string{})
	notes := filepath.Join(dest, "notes~1.txt")
	write(t, notes, "a file with an unlucky literal name")

	if err := Clear(dest, []config.Entry{{Path: "notes~1.txt"}}); err != nil {
		t.Fatalf("the take-back refused a record naming notes~1.txt: %v", err)
	}
	if _, err := os.Stat(notes); !os.IsNotExist(err) {
		t.Errorf("an alias-shaped name that resolves onto itself was spared as if it were reserved: %v", err)
	}
}

// TestAPlainRunStillCarriesAnAliasShapedNameThatResolvesToItself guards the
// whole resolution layer against over-refusal. notes~1.txt is spelled the
// way an alias is spelled, and the copy asks the volume about it on every
// run -- but the only name it can resolve to is its own, and its own name
// is reserved under none, so the file is the rules entry's to copy and to
// skip like any other. A guard that spared every odd spelling would have
// stopped copying half of what an agent keeps.
func TestAPlainRunStillCarriesAnAliasShapedNameThatResolvesToItself(t *testing.T) {
	home, dest := useProfile(t, []string{"tools"})
	write(t, filepath.Join(home, "tools", "notes~1.txt"), "a plain file an agent needs")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, "tools", "notes~1.txt")); got != "a plain file an agent needs" {
		t.Fatalf("an alias-shaped name that resolves onto itself was not copied: %q", got)
	}

	// The second run must skip it, the way it skips any unchanged file. The
	// stamps say what that run did -- copied or skipped -- better than a
	// number restated by hand.
	plantStaleStamps(t, dest)
	fill(t, dest)
	if copied, skipped := whatTheRunDid(t, filepath.Join(dest, "tools")); copied != 0 || skipped != 1 {
		t.Errorf("the second run copied %d and skipped %d, want the one file skipped", copied, skipped)
	}
}
