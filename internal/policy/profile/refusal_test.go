package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// TestCopyRefusesADestinationItWasNotGiven guards the sharp edge: filling a
// profile starts by clearing it of what the list no longer names, so a
// mistaken argument is not a copy into the wrong place but a deletion of one.
func TestCopyRefusesADestinationItWasNotGiven(t *testing.T) {
	for _, dest := range []string{"", ".", "profile"} {
		if _, _, err := Copy(dest, nil, nil); err == nil {
			t.Errorf("a profile at %q was accepted, and clearing it would have run", dest)
		}
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Copy(file, nil, nil); err == nil {
		t.Error("a file was accepted as a profile to fill")
	}
	missing := filepath.Join(t.TempDir(), "never-made")
	if _, _, err := Copy(missing, nil, nil); err == nil {
		t.Error("a directory that does not exist was accepted as a profile to fill")
	}
}

func TestCopyRefusesARecordedNameThatClimbsOutOfTheProfile(t *testing.T) {
	_, dest := useProfile(t, []string{".claude"})
	outside := filepath.Join(filepath.Dir(dest), "not-the-profile")
	precious := filepath.Join(outside, "precious.txt")
	write(t, precious, "somebody else's")

	if _, _, err := Copy(dest, []config.Entry{{Path: "../not-the-profile"}}, nil); err == nil {
		t.Error("a recorded name pointing outside the profile was acted on")
	}
	if _, err := os.Stat(precious); err != nil {
		t.Errorf("it deleted something outside the profile: %v", err)
	}
}

// junctionTo makes a real directory junction, the kind a sandbox can make in
// its own profile without any privilege at all. Skips where the machine will
// not make one, rather than passing quietly.
// TestCopyCannotBeWalkedOutOfTheProfileThroughAJunction is the regression
// guard for the worst thing in this file's history, and the reason every
// write and delete below goes through an os.Root.
//
// The sandbox owns its own profile. It needs no privilege to replace a
// directory in it with a junction pointing anywhere -- and this code runs as
// the person who owns the machine, with their rights. Before the root, the
// next run followed that junction and did exactly what it does to a copy:
// overwrote the files it thought it was refreshing and deleted the ones it
// thought were left over. Measured, on a real junction: both.
func TestCopyCannotBeWalkedOutOfTheProfileThroughAJunction(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "keep.txt"), "from the source")

	outside := t.TempDir()
	precious := filepath.Join(outside, "precious.txt")
	write(t, precious, "do not touch")
	collide := filepath.Join(outside, "keep.txt")
	write(t, collide, "this content must survive")

	copied := fill(t, dest)

	// The sandbox swaps the copied directory for a junction to somebody
	// else's.
	link := filepath.Join(dest, ".claude")
	if err := os.RemoveAll(link); err != nil {
		t.Fatal(err)
	}
	junctionTo(t, link, outside)

	if _, _, err := Copy(dest, copied, lastPrints[dest]); err != nil {
		t.Fatalf("the run could not go on past a junction the sandbox left: %v", err)
	}

	if _, err := os.Stat(precious); err != nil {
		t.Errorf("a file outside the profile was deleted through the junction: %v", err)
	}
	if got := read(t, collide); got != "this content must survive" {
		t.Errorf("a file outside the profile was overwritten through the junction: %q", got)
	}
	// And the sandbox does not get to pin the name either: the link is
	// replaced with the real copy, which is what the run was for.
	if got := read(t, filepath.Join(dest, ".claude", "keep.txt")); got != "from the source" {
		t.Errorf("the entry was not copied over the junction: %q", got)
	}
}

// And the link itself is still wuserbox's to remove: refusing to follow a
// junction must not mean a sandbox can pin a name in its own profile forever
// by putting one there.
func TestCopyCanStillClearAJunctionTheSandboxLeftBehind(t *testing.T) {
	home, dest := useProfile(t, []string{".claude"})
	write(t, filepath.Join(home, ".claude", "keep.txt"), "from the source")
	outside := t.TempDir()
	write(t, filepath.Join(outside, "precious.txt"), "do not touch")

	copied := fill(t, dest)
	link := filepath.Join(dest, ".claude")
	if err := os.RemoveAll(link); err != nil {
		t.Fatal(err)
	}
	junctionTo(t, link, outside)

	// Taken off the list, so the next run has to clear it.
	if err := (&config.Config{Profile: config.Entries([]string{})}).Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Copy(dest, copied, lastPrints[dest]); err != nil {
		t.Fatalf("clearing a junction the sandbox left behind failed: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("the junction is still in the profile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "precious.txt")); err != nil {
		t.Errorf("clearing the junction reached what it pointed at: %v", err)
	}
}

// TestCopyRefusesAnEntryNamingTheProfileRoot is the regression guard for the
// worst path a rules file can spell. within accepts "." outright, and it
// accepts "foo/.." too, because filepath.Clean turns both into ".": an
// entry of "." makes the source the user's whole profile and dst -- inside
// the root -- the sandbox's whole profile. Copy would then mirror one onto
// the other: copy everything the user owns into the sandbox, and delete
// from the sandbox everything the user's profile does not have, the
// sandbox's own registry hive among it.
//
// Written to show that actually happening on the unfixed code, not merely
// that an error comes back: a file elsewhere in the user's profile lands in
// the sandbox's, and a file that is the sandbox's own -- never on any list,
// the way NTUSER.DAT never is -- gets removed for not being in the source.
func TestCopyRefusesAnEntryNamingTheProfileRoot(t *testing.T) {
	for _, path := range []string{".", "foo/.."} {
		t.Run(path, func(t *testing.T) {
			home, dest := useProfile(t, []string{path})
			write(t, filepath.Join(home, "elsewhere-in-the-profile.txt"), "not meant for any sandbox")
			write(t, filepath.Join(dest, "NTUSER.DAT"), "the sandbox's own registry hive")

			_, _, err := Copy(dest, nil, nil)
			if err == nil {
				t.Fatalf("path %q: an entry naming the profile root was accepted", path)
			}

			if _, statErr := os.Stat(filepath.Join(dest, "NTUSER.DAT")); statErr != nil {
				t.Errorf("path %q: the sandbox's own registry hive was removed: %v", path, statErr)
			}
			if _, statErr := os.Stat(filepath.Join(dest, "elsewhere-in-the-profile.txt")); statErr == nil {
				t.Errorf("path %q: the whole user profile was mirrored into the sandbox's", path)
			}
		})
	}
}

// TestCopyRefusesProfileEntriesRepeatedWithDifferentLimits is the guard
// against the duplicate that reads as merely redundant and is not: {path:
// .codex, exclude: [sessions/**]} followed by the bare ".codex" names the
// same path twice, but the second entry carries no exclusion, so its own
// mirroring deletes what the first entry's exclusion was protecting -- the
// sessions an agent running inside the sandbox actually wrote.
//
// Written to show that deletion actually happening on the unfixed code, not
// merely that an error comes back.
func TestCopyRefusesProfileEntriesRepeatedWithDifferentLimits(t *testing.T) {
	protected := []config.Entry{{Path: ".codex", Exclude: config.Masks([]string{"sessions/**"})}}
	home, dest := useProfileEntries(t, protected)
	write(t, filepath.Join(home, ".codex", "auth.json"), `{"token":"real"}`)

	copied := fill(t, dest)

	// What an agent inside the sandbox actually wrote there -- never copied
	// in by any entry, and exactly what the first entry's exclusion exists
	// to protect.
	write(t, filepath.Join(dest, ".codex", "sessions", "mysession.txt"), "a real session")

	conflicting := append([]config.Entry{}, protected...)
	conflicting = append(conflicting, config.Entry{Path: ".codex"})
	if err := (&config.Config{Profile: conflicting}).Save(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := Copy(dest, copied, lastPrints[dest]); err == nil {
		t.Fatal("profile: repeating .codex with different limits was accepted")
	}

	if got := read(t, filepath.Join(dest, ".codex", "sessions", "mysession.txt")); got != "a real session" {
		t.Errorf("the session the first entry's exclusion protected did not survive: %q", got)
	}
}

// TestCopyRefusesANegativeDepthRatherThanDeletingWhatItDidNotCopy is the
// guard on the typo that an ordinary run used to pass. With a bound of -1
// every path is out of reach: reachesWithin put every exclude mask out of
// reach and copiesFile refused every file, so nothing was copied and nothing
// went on the present list -- and the mirroring then removed what the
// destination already held as stray, the copied credentials and the file the
// exclusion was protecting alike. depth: -1 is a number nobody meant to
// write, and taken at face value it silently turned every protection off.
func TestCopyRefusesANegativeDepthRatherThanDeletingWhatItDidNotCopy(t *testing.T) {
	home, dest := useProfileEntries(t, []config.Entry{
		{Path: "agent", Exclude: config.Masks([]string{"*.log"})},
	})
	write(t, filepath.Join(home, "agent", "auth.json"), `{"token":"real"}`)
	write(t, filepath.Join(home, "agent", "work.log"), "work")
	// What the agent inside the sandbox wrote there, and what the exclusion
	// exists to spare -- never copied in by any run.
	write(t, filepath.Join(dest, "agent", "work.log"), "the sandbox's own log")

	copied := fill(t, dest)
	if !reflect.DeepEqual(pathsOf(copied), []string{"agent"}) {
		t.Fatalf("nothing was copied in the first place, so this test proves nothing: %v", copied)
	}
	if got := read(t, filepath.Join(dest, "agent", "work.log")); got != "the sandbox's own log" {
		t.Fatalf("the exclusion did not hold on the run before the typo, so this test proves nothing: %q", got)
	}

	// The typo. The same entry, one number nobody meant to write.
	negative := -1
	if err := (&config.Config{Profile: []config.Entry{{
		Path:    "agent",
		Depth:   &negative,
		Exclude: config.Masks([]string{"*.log"}),
	}}}).Save(); err != nil {
		t.Fatal(err)
	}

	_, _, err := Copy(dest, copied, lastPrints[dest])
	if err == nil {
		t.Error("a rules file carrying depth: -1 was accepted by an ordinary run")
	}
	for _, kept := range []struct {
		path, want string
	}{
		{filepath.Join("agent", "auth.json"), `{"token":"real"}`},
		{filepath.Join("agent", "work.log"), "the sandbox's own log"},
	} {
		data, err := os.ReadFile(filepath.Join(dest, kept.path))
		if err != nil {
			t.Errorf("%s did not survive the refused run: %v", kept.path, err)
			continue
		}
		if string(data) != kept.want {
			t.Errorf("%s was disturbed by the refused run: %q", kept.path, data)
		}
	}
}

// TestARecordWhoseLimitsCannotBindIsRefused is the other door a negative
// depth arrives through. Clear reads the record rather than the rules file,
// and a run before the copier's refusal went in wrote the rules file's
// impossible depth straight into the record. The recorded limits are the
// only thing that says what the sandbox keeps on the way back out, so the
// taking-back refuses rather than guesses: with the entry's own depth at -1
// the walk would spare everything and report success while taking back
// nothing, and with a mask's depth at -1 the mask reaches nothing and its
// exclusion stops protecting exactly when the deletion is happening.
func TestARecordWhoseLimitsCannotBindIsRefused(t *testing.T) {
	negative := -1
	for _, tc := range []struct {
		name  string
		entry config.Entry
	}{
		{"entry depth", config.Entry{Path: "agent", Depth: &negative}},
		{"mask depth", config.Entry{Path: "agent", Exclude: []config.Mask{{Pattern: "work.log", Depth: &negative}}}},
	} {
		t.Run("clear/"+tc.name, func(t *testing.T) {
			_, dest := useProfileEntries(t, nil)
			write(t, filepath.Join(dest, "agent", "work.log"), "the sandbox's own log")

			if err := Clear(dest, []config.Entry{tc.entry}); err == nil {
				t.Error("a record whose limits cannot bind was acted on")
			}
			if data, err := os.ReadFile(filepath.Join(dest, "agent", "work.log")); err != nil {
				t.Errorf("the file the recorded limits could not speak for did not survive: %v", err)
			} else if string(data) != "the sandbox's own log" {
				t.Errorf("the file was disturbed: %q", data)
			}
		})
	}

	// The same record reaches an ordinary fill: Copy hands previously to
	// forget, and forget is where the refusal has to stand for both doors.
	t.Run("copy/forget", func(t *testing.T) {
		_, dest := useProfileEntries(t, nil)
		write(t, filepath.Join(dest, "agent", "work.log"), "the sandbox's own log")

		if _, _, err := Copy(dest, []config.Entry{{
			Path:    "agent",
			Exclude: []config.Mask{{Pattern: "work.log", Depth: &negative}},
		}}, nil); err == nil {
			t.Error("a record whose limits cannot bind was acted on by a fill")
		}
		if data, err := os.ReadFile(filepath.Join(dest, "agent", "work.log")); err != nil {
			t.Errorf("the file did not survive the refused run: %v", err)
		} else if string(data) != "the sandbox's own log" {
			t.Errorf("the file was disturbed: %q", data)
		}
	})
}
