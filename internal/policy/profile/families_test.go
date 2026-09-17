package profile

import (
	"slices"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// The widths the shapes actually allow, generated rather than listed: the
// TxR index at one to five digits -- the fuzz that backed commit 8271219
// generated indices of one digit only, so a ? run wider than the two
// positions a decRun encodes never arose against a variable-length part,
// and "*.TxR.???.regtrans-ms" reached a real three-digit member unrefused
// -- the container counter at its fixed twenty, and GUIDs in both the
// capitals Windows and this file's own examples spell.
var famTestIndices = []string{"0", "1", "9", "10", "42", "99", "100", "123", "999", "1000", "4321", "99999"}

var famTestGUIDs = []string{
	"53b39e3d-18c4-11ea-a811-000d3aa4692b",
	"A0876E4C-1CB1-11D9-9669-0800200C9A66",
}

// famTestMembers spells concrete family members, lowercase the way no real
// profile spells them, so the fold every comparison here goes through is
// exercised rather than assumed.
func famTestMembers() []string {
	var members []string
	for _, hive := range []struct{ dir, base string }{
		{"", "ntuser.dat"},
		{usrClassDir, "usrclass.dat"},
	} {
		prefix := hive.dir
		if prefix != "" {
			prefix += "/"
		}
		for _, guid := range famTestGUIDs {
			members = append(members,
				prefix+hive.base,
				prefix+hive.base+".log1",
				prefix+hive.base+"{"+guid+"}.tm.blf",
				prefix+hive.base+"{"+guid+"}.tmcontainer00000000000000000001.regtrans-ms",
				prefix+hive.base+"{"+guid+"}.tmcontainer00000000000000000042.regtrans-ms",
				prefix+hive.base+"{"+guid+"}.txr.blf",
			)
			for _, idx := range famTestIndices {
				members = append(members, prefix+hive.base+"{"+guid+"}.txr."+idx+".regtrans-ms")
			}
		}
	}
	return members
}

// famTestGlobs spells the glob language the refusal has to answer for,
// built off real member names so every ? run and star sits where a
// family's varying part sits.
func famTestGlobs() []string {
	globs := make(map[string]bool)
	add := func(g string) { globs[g] = true }

	// ? runs of every length up to eight -- a few past the five-digit
	// index -- over three heads: the bare star, the whole GUID as {*},
	// and one GUID spelled out. Both hives, the class hive also spelled
	// with its directory so the anchored door (pathReaches) is asked too.
	for _, base := range []string{"ntuser.dat", "usrclass.dat"} {
		dir := ""
		if base == "usrclass.dat" {
			dir = usrClassDir + "/"
		}
		for _, head := range []string{
			dir + "*",
			dir + base + "{*}.",
			dir + base + "{" + famTestGUIDs[0] + "}.",
		} {
			for l := 1; l <= 8; l++ {
				add(head + "txr." + strings.Repeat("?", l) + ".regtrans-ms")
			}
		}
	}

	// The fixed widths at their own lengths and one past: a GUID's hex
	// run, the GUID whole, the container counter at its twenty. A run one
	// short matches no member and costs nothing to ask.
	add("usrclass.dat{" + strings.Repeat("?", 36) + "}.tm.blf")
	add("usrclass.dat{" + strings.Repeat("?", 37) + "}.tm.blf")
	add("usrclass.dat{" + famTestGUIDs[1][:12] + strings.Repeat("?", 12) + "}.tm.blf")
	add("usrclass.dat{" + famTestGUIDs[1][:12] + strings.Repeat("?", 13) + "}.tm.blf")
	add("usrclass.dat{*}.tmcontainer" + strings.Repeat("?", 20) + ".regtrans-ms")
	add("usrclass.dat{*}.tmcontainer" + strings.Repeat("?", 21) + ".regtrans-ms")
	add("*{????????-????-????-????-????????????}.txr.blf")

	// The two mixed, over the index.
	add("*.txr.?*")
	add("*.txr.??*")
	add("*.txr.???*")
	add("*.txr.*?")
	add("*.txr.?*?")
	add("usrclass.dat{*.txr.???*.regtrans-ms")

	// A * in every position, and ? runs of one to six over every stretch
	// from the brace on, of members carrying the widths that matter:
	// indices of three, four and five digits, both GUID capitals, and the
	// counter.
	for _, m := range []string{
		usrClassDir + "/usrclass.dat{53b39e3d-18c4-11ea-a811-000d3aa4692b}.txr.123.regtrans-ms",
		usrClassDir + "/usrclass.dat{A0876E4C-1CB1-11D9-9669-0800200C9A66}.txr.4321.regtrans-ms",
		"ntuser.dat{53b39e3d-18c4-11ea-a811-000d3aa4692b}.txr.99999.regtrans-ms",
		usrClassDir + "/usrclass.dat{A0876E4C-1CB1-11D9-9669-0800200C9A66}.tmcontainer00000000000000000042.regtrans-ms",
		usrClassDir + "/usrclass.dat{53b39e3d-18c4-11ea-a811-000d3aa4692b}.tm.blf",
	} {
		name := m[strings.LastIndexByte(m, '/')+1:]
		brace := strings.IndexByte(name, '{')
		for i := 0; i < len(name); i++ {
			add(name[:i] + "*" + name[i+1:])
		}
		for i := brace; i < len(name); i++ {
			for l := 1; l <= 6 && i+l <= len(name); l++ {
				add(name[:i] + strings.Repeat("?", l) + name[i+l:])
			}
		}
	}

	out := make([]string, 0, len(globs))
	for g := range globs {
		out = append(out, g)
	}
	slices.Sort(out)
	return out
}

// TestNoGlobMatchingAFamilyMemberEscapesTheRefusal re-measures, as an
// ordinary test, the claim commit 8271219 could then only write in its
// message: every glob matching a real family member is refused. It pairs
// members spelled across the widths the shapes allow with globs built to
// cross those widths -- ? runs past the index, a * in every position, the
// two mixed -- and asserts the soundness the whole refusal stands on: if
// the walk's own matcher (matchMask) matches a member, the guard
// (reservedFamilyReachedBy) refuses the glob. A miss is the silent
// direction: the glob is accepted, the walk deletes, the run reports
// success.
//
// Exhaustive it is not, and this comment is where it says so. The globs
// carry at most two wildcards, ? runs stop at eight, TxR indices at five
// digits, and the fold's stranger equivalences are not swept; a property
// test that reads as a proof is worse than one that says where it stops.
// The refusal's other doors -- the ancestor directories, the profile root
// itself -- keep their own tests in cleanup_test.go.
func TestNoGlobMatchingAFamilyMemberEscapesTheRefusal(t *testing.T) {
	members := famTestMembers()
	witness := "*.txr.???.regtrans-ms"
	threeDigit := usrClassDir + "/usrclass.dat{" + famTestGUIDs[0] + "}.txr.123.regtrans-ms"
	if !matchMask(witness, threeDigit) {
		t.Fatalf("the harness lost its own witness: %q no longer matches %s", witness, threeDigit)
	}

	var mustRefuse []string
	for _, g := range famTestGlobs() {
		for _, m := range members {
			if matchMask(g, m) {
				mustRefuse = append(mustRefuse, g)
				break
			}
		}
	}
	if len(mustRefuse) == 0 {
		t.Fatal("no generated glob matched any member, so the property below would hold vacuously")
	}

	misses := 0
	for _, g := range mustRefuse {
		if _, reached := reservedFamilyReachedBy(g); !reached {
			misses++
			if misses <= 10 {
				t.Errorf("glob %q matches a real family member and was not refused -- the walk would delete it and the run would report success", g)
			}
		}
	}
	if misses > 10 {
		t.Errorf("and %d more globs matched members without being refused", misses-10)
	}
}

// TestTheWidthQuestionStillAcceptsTheSandboxesOwn pins the companion
// property the soundness sweep must not cost: the sandbox's own scratch,
// its caches and its sessions stay clearable. The class hive's directory
// shares no prefix with any of them -- families.go's reason a shape
// anchored there cannot reach them -- and a ? run is a question about one
// name, not one directory, so widths learned on the families must not
// teach the guard to refuse these.
func TestTheWidthQuestionStillAcceptsTheSandboxesOwn(t *testing.T) {
	for _, glob := range []string{
		"AppData/Local/Temp/**",
		"AppData/Local/Temp",
		"Temp",
		"Temp/??.log",
		"*.tmp",
		"AppData/Local/Roaming/**",
		".codex/sessions/**",
	} {
		if err := CleanupNamesSomethingReserved(config.Masks([]string{glob})); err != nil {
			t.Errorf("cleanup glob %q was refused: %v -- the guard reached past the profile service's own files", glob, err)
		}
	}
}
