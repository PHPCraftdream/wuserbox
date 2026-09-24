package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// TestASecondRecordedSpellingBehindAnUnresolvableAliasStopsTheCopyAndTheRecordSurvives
// is the round-13 review's static scenario, measured end to end through
// the public Copy: a legacy record whose entries are spelled through an
// alias prefix of a destination directory another program holds shut. The
// first recorded spelling through that prefix asks the volume about it and
// gets a refusal -- an open that is not the volume's own nothing -- and
// the second reads that refusal out of the alias memo, where the old code
// kept it as the empty canonical spelling beside it. Read that way, the
// second spelling came back an absence: the record's membership vouched
// absent, Copy reported success, and the copy outlived the record that
// named it with nothing left able to ask where it stood.
func TestASecondRecordedSpellingBehindAnUnresolvableAliasStopsTheCopyAndTheRecordSurvives(t *testing.T) {
	home, dest := useProfile(t, []string{"APPDATA/auth.json"})
	// The standing copies from the earlier run that spelled both entries
	// through the alias: the class hive at the family path the profile
	// service built it under, and the agent's own file beside it. Both sit
	// under AppData while the rules entry spells the directory APPDATA --
	// a record spelled through an alias is legitimate, and the suite's own
	// reserved tests clear exactly such records.
	write(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"), profileServiceHive)
	write(t, filepath.Join(dest, "AppData", "auth.json"), `{"token":"real"}`)
	write(t, filepath.Join(dest, "NTUSER.DAT"), profileServiceHive)
	// The legacy record, in the review's order: the root hive's own
	// padded spelling first, then the two copies spelled through the
	// alias -- the class hive, which the reserved tables know without
	// asking the volume anything, and the agent's file, which is the
	// entry the rules still name.
	previously := []config.Entry{
		{Path: "NTUSER.DAT."},
		{Path: "APPDATA/Local/Microsoft/Windows/UsrClass.dat"},
		{Path: "APPDATA/auth.json"},
	}
	// The source of the rules entry is gone.
	if err := os.Remove(filepath.Join(home, "APPDATA", "auth.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	release := lockExclusive(t, filepath.Join(dest, "AppData"), true)
	holdProof(t, root, "APPDATA")

	// forget goes through whole: the hive's entry is spared by the name
	// the tables know it under, asked with no open of the shut directory
	// anywhere, and the copy's entry is the one the list still names. In
	// the copy's own index the first recorded spelling through the alias
	// keeps the refusal the volume gave for its prefix, and the second
	// reads the very same refusal out of the memo -- where the old code
	// read an absence, retired the entry and reported the run a success.
	copied, prints, err := Copy(dest, previously, nil)
	if err == nil {
		t.Fatal("a copy whose record spelled two entries through a directory nothing could ask about reported success and left the record naming nothing")
	}
	if !strings.Contains(err.Error(), "auth.json") {
		t.Errorf("the refusal did not name the entry it stopped on: %v", err)
	}
	release()

	// The run stopped before it touched anything: both copies stand, with
	// the hives beside them.
	for _, name := range []string{
		filepath.Join(dest, "AppData", "auth.json"),
		filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
		filepath.Join(dest, "NTUSER.DAT"),
	} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("the run that could not ask disturbed %s: %v", name, err)
		}
	}
	if got := read(t, filepath.Join(dest, "AppData", "auth.json")); got != `{"token":"real"}` {
		t.Errorf("the copy behind the hold was disturbed by the run that could not ask about it: %q", got)
	}
	if got := read(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")); got != profileServiceHive {
		t.Errorf("the hive behind the hold was disturbed by the run that could not ask about it: %q", got)
	}

	// fillProfile's partial union is what carries the record over a failed
	// run: whatever came back is unioned with what stood before, so every
	// entry survives the refusal and the next run asks again.
	survived := DedupeEntries(dest, append(append([]config.Entry{}, copied...), previously...))
	want := []string{"NTUSER.DAT.", "APPDATA/Local/Microsoft/Windows/UsrClass.dat", "APPDATA/auth.json"}
	got, wantSorted := append([]string{}, pathsOf(survived)...), append([]string{}, want...)
	sort.Strings(got)
	sort.Strings(wantSorted)
	if !reflect.DeepEqual(got, wantSorted) {
		t.Fatalf("the record the failed run left behind came back as %v, want %v: an entry spelled through the unresolvable alias was retired anyway",
			pathsOf(survived), want)
	}

	// The retry, once the hold lets go: the copy is witnessed where it
	// stands, its source still gone, and the entry stays on the record.
	copied, _, err = Copy(dest, survived, prints)
	if err != nil {
		t.Fatalf("the retry after the hold let go failed: %v", err)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"APPDATA/auth.json"}) {
		t.Errorf("the retry's record came back as %v, want the entry whose copy still stands", pathsOf(copied))
	}

	// And the record the retry left is the one a later --no-ai needs: the
	// take-back spares both hives -- the root one by the name its padded
	// spelling resolves to, the class one by the tables' own reading of
	// the alias -- and takes the copy back.
	if err := Clear(dest, previously); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dest, "NTUSER.DAT")); got != profileServiceHive {
		t.Errorf("the take-back took the registry hive a record spelled with the volume's own padding: %q", got)
	}
	if got := read(t, filepath.Join(dest, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")); got != profileServiceHive {
		t.Errorf("the take-back took the class hive a record spelled through the alias: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "AppData", "auth.json")); !os.IsNotExist(err) {
		t.Error("the copy outlived its source, the record and the take-back all three")
	}
}
