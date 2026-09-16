package facts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/profile"
)

// A record that round-trips byte for byte is what makes the skip trustworthy:
// whatever the copier wrote last run is exactly what this run compares
// against. The key carrying a space pins the format decision that the path
// goes last on its line, so a path needs no quoting to survive.
func TestAPrintRecordRoundTrips(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-prints-rt-00000000"
	want := map[string]profile.Print{
		".claude.json":       {Size: 1024, ModNanos: 1726400000000000000},
		"my dir/config.toml": {Size: 256, ModNanos: 1726400000000000001},
		".codex/auth.json":   {Size: 88, ModNanos: 1726400000000000002},
	}
	if err := RecordPrints(name, want); err != nil {
		t.Fatal(err)
	}
	got, err := Prints(name)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the record came back as %v, want %v", got, want)
	}
}

// One bad line poisons the whole record -- half a cache is a cache that
// sometimes lies, and the safe side is copying everything. A well-formed
// line beside a malformed one must therefore be thrown away with it.
func TestACorruptPrintRecordYieldsNothing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-prints-corrupt-00000000"
	if err := os.MkdirAll(filepath.Dir(PrintsList(name)), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := "16384 1726400000000000000 good/path\nand now something that is not a fingerprint\n"
	if err := os.WriteFile(PrintsList(name), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Prints(name)
	if err != nil {
		t.Fatalf("a corrupt record came back as an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a corrupt record came back as %v, want nothing", got)
	}
}

// A sandbox never filled, or filled by a version that kept no prints, has no
// record to read -- and that is the ordinary first run, not a failure.
func TestAMissingPrintRecordYieldsNothing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	got, err := Prints("wub-prints-missing-00000000")
	if err != nil {
		t.Fatalf("a missing record came back as an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a missing record came back as %v, want nothing", got)
	}
}

// An empty record is the state a --no-ai run leaves behind after taking a
// profile back; the next run must read it as nothing known, not as a mistake.
func TestAnEmptyPrintRecordYieldsNothing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	const name = "wub-prints-empty-00000000"
	if err := RecordPrints(name, nil); err != nil {
		t.Fatal(err)
	}
	got, err := Prints(name)
	if err != nil {
		t.Fatalf("an empty record did not read back: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("an empty record came back as %v, want nothing", got)
	}
}
