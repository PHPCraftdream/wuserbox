package account

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// TestWhatTheSeededHiveAnswersItsOwnAccount measures, where the rights
// are, the picture docs/investigations/a-hive-per-slot.md settled: the
// hive MakeProfile seeds answers the account it was seeded for everywhere
// it looks -- the root, HKCU\Software, and HKCU\Software\Classes, which is
// not the seeded hive at all but UsrClass.dat, permissioned by the profile
// service. It was called TestWhereTheSeededHiveRefusesItsOwnAccount until
// the fix below, and the finding that put it here is worth the sentence the
// name no longer carries: measured 2026-09-17, the permission list on the
// root reached nothing below it, so keys the first load created -- Software
// among them -- took their creator's default list, which does not name the
// account. The entries carry their inheritance down since the fix of the
// same day, and the refusal transcript they ended is quoted in the
// investigation beside the lists that caused it.
//
// The output is the finding, not the pass or fail: one logon per probe it
// asks reg.exe which writes the account's own hive accepts, then loads the
// hive and its UsrClass.dat to print, in words, who owns each key and what
// each permission list grants -- the key the first load created beside the
// keys the account makes, so the difference is in the log and not in
// somebody's head.
//
// What it asserts is the whole picture above: the account is refused
// nowhere in its own hive. When that moves the assertions go red carrying
// the new report, and the investigation and docs/limits.md are the two
// things to update in the same change.
//
// It builds one real account and removes it, the lifecycle test's way, and
// needs administrator rights the same way; it says so when it skips.
func TestWhatTheSeededHiveAnswersItsOwnAccount(t *testing.T) {
	requireAdmin(t)

	dir := filepath.Join(os.TempDir(), fmt.Sprintf("wub-hive-measure-%d", os.Getpid()))
	// The cleanups run in the order the investigation says --rm must keep:
	// nothing holding the hive first (its own cleanup, registered when the
	// test loads it below), then the profile record, then the account,
	// then the directory.
	t.Cleanup(func() { removeMeasureDir(t, dir) })

	password, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := Add(hiveMeasureName, "wuserbox hive measurement, removed by its test", password); err != nil {
		t.Fatalf("creating the measurement account: %v", err)
	}
	t.Cleanup(func() { _ = Delete(hiveMeasureName) })

	value, err := sid.Lookup(hiveMeasureName)
	if err != nil {
		t.Fatalf("the measurement account was not found: %v", err)
	}
	if err := HideFromSignIn(hiveMeasureName); err != nil {
		t.Fatalf("hiding the measurement account from sign-in: %v", err)
	}
	if err := DenyRemoteLogon(hiveMeasureName); err != nil {
		t.Fatalf("denying the measurement account remote logon: %v", err)
	}
	if err := MakeProfile(dir, value); err != nil {
		t.Fatalf("seeding the profile and its hive: %v", err)
	}
	if err := RegisterProfile(value, dir); err != nil {
		t.Fatalf("registering the profile so the first logon loads the seeded hive: %v", err)
	}

	regExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "reg.exe")
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if _, err := os.Stat(regExe); err != nil {
		t.Fatalf("reg.exe is not where Windows keeps it, so nothing can be asked: %v", err)
	}
	if _, err := os.Stat(cmdExe); err != nil {
		t.Fatalf("cmd.exe is not where Windows keeps it, so nothing can be asked: %v", err)
	}

	// The first probe is the finding's own write, on the first logon of
	// this hive, so the first load happens under it exactly as it did in
	// the probe that found the refusal. Each probe is its own logon, the
	// way a run starts everything, which also means a key one probe
	// creates meets its next write through a fresh load of the hive.
	out := filepath.Join(dir, "Temp", "probe-out.txt")
	env := probeEnv(dir)
	runAsProbe := func(what, args string) probeResult {
		_ = os.Remove(out)
		line := fmt.Sprintf(`%s /d /c %s %s > "%s" 2>&1`, cmdExe, regExe, args, out)
		type finished struct {
			exit int
			err  error
		}
		done := make(chan finished, 1)
		go func() {
			exit, err := proc.RunAsAccount(hiveMeasureName, password, line, dir, env)
			done <- finished{exit, err}
		}()
		// reg.exe answers in milliseconds; a probe still running a
		// minute in is a machine this test cannot measure or clean up
		// after, so that is said rather than waited out. The job object
		// RunAsAccount puts the probe in ends it when this process's
		// handles are closed, so nothing outlives the test run.
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("the probe %q never started as %s -- the logon itself failed, so nothing was measured: %v", what, hiveMeasureName, r.err)
			}
			text, _ := os.ReadFile(out)
			return probeResult{exit: r.exit, text: string(text)}
		case <-time.After(time.Minute):
			t.Fatalf("the probe %q is still running a minute in; reg.exe does not do that, so the machine this ran on is not in a state worth measuring", what)
			return probeResult{}
		}
	}

	type probe struct {
		what string
		args string
	}
	probes := []probe{
		{"create HKCU\\Software\\wub-probe (the write the finding measured)", `add HKCU\Software\wub-probe /f`},
		{"create a nested key below HKCU\\Software\\wub-probe", `add HKCU\Software\wub-probe\nested /f`},
		{"create HKCU\\Software\\Classes\\wub-probe", `add HKCU\Software\Classes\wub-probe /f`},
		{"read HKCU\\Software", `query HKCU\Software`},
		{"write a value on the root, HKCU itself", `add HKCU /ve /d wub /f`},
		{"create HKCU\\wub-rootkey, a subkey of the root", `add HKCU\wub-rootkey /f`},
		{"write a value on HKCU\\wub-rootkey, which the account itself created", `add HKCU\wub-rootkey /ve /d wub /f`},
		{"write a value on HKCU\\Software itself", `add HKCU\Software /ve /d wub /f`},
	}
	results := make([]probeResult, len(probes))
	for i, p := range probes {
		results[i] = runAsProbe(p.what, p.args)
	}

	t.Log("what the account's own writes did, one logon each, reg.exe's own words quoted:")
	for i, p := range probes {
		t.Logf("  %-64s exit %d: %s", p.what, results[i].exit, oneLine(results[i].text))
	}

	t.Log("who owns each key and what each permission list says, read from the hive once the logons let go of it:")
	describeSeededHive(t, dir)

	// What the measurement found, the first time it ran, on 2026-09-17, is
	// the investigation's refusal transcript, quoted with the permission
	// lists that caused it: the account reached the root and everything it
	// created there itself, and reached nothing the first load created for
	// it -- exactly a list granted on the root and nowhere below it. The
	// entries carry their inheritance down since the fix of the same day,
	// and the shape below is the account's own writes succeeding everywhere
	// in the hive it was seeded for.
	//
	// Asserted rather than reported now, because reported facts do not
	// notice when they stop being true. When the picture moves again these
	// go red carrying the new report, and the same rule holds: this test,
	// the account in docs/investigations/a-hive-per-slot.md and the entry
	// in docs/limits.md are corrected in the same change, with the new
	// descriptors from the report above pasted into the investigation.
	for _, want := range []struct {
		at      int
		refused bool
		because string
	}{
		{0, false, "Software is born inheriting the root's list now that the entries carry their inheritance down, instead of taking its creator's default"},
		{1, false, "a key nested below Software inherits the same list, not only Software itself"},
		{2, false, "Software\\Classes is UsrClass.dat, and the profile service permissions its root to the account with entries that reach the subkeys"},
		{3, false, "the list Software inherits grants reading as much as writing -- the defect refused this read, which is how it showed on both sides"},
		{4, false, "the root itself is where the tightened list grants the account everything"},
		{5, false, "a key the account creates under the root is the account's own, permissioned from its creator"},
		{6, false, "and stays the account's own -- the inheritance changes who reaches the hive, not who owns what the account makes"},
		{7, false, "Software accepts a value because the list it was born with is the root's, inherited, and it names the account"},
	} {
		if refused := results[want.at].exit != 0; refused != want.refused {
			verb := "was refused"
			if !want.refused {
				verb = "succeeded"
			}
			t.Errorf("%q no longer %s, and the picture this test exists to hold has moved -- %s. reg said: %s",
				probes[want.at].what, verb, want.because, oneLine(results[want.at].text))
		}
	}
}

// probeEnv is what a probe is handed: this process's own environment with
// the profile-rooted variables replaced to point inside the measurement's
// profile, the same set a real run replaces in exec.childEnv. A probe that
// inherited this process's USERPROFILE would be told it is someone it is
// not. Sorted by name at the end for the reason childEnv sorts: a block
// that changes shape between two runs is one more thing to rule out.
func probeEnv(profileDir string) []string {
	overrides := map[string]string{
		"USERPROFILE":  profileDir,
		"HOME":         profileDir,
		"APPDATA":      filepath.Join(profileDir, "AppData", "Roaming"),
		"LOCALAPPDATA": filepath.Join(profileDir, "AppData", "Local"),
		"TEMP":         filepath.Join(profileDir, "Temp"),
		"TMP":          filepath.Join(profileDir, "Temp"),
		"USERNAME":     hiveMeasureName,
		"USERDOMAIN":   os.Getenv("COMPUTERNAME"),
		"HOMEDRIVE":    filepath.VolumeName(profileDir),
		"HOMEPATH":     strings.TrimPrefix(profileDir, filepath.VolumeName(profileDir)),
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, replaced := overrides[strings.ToUpper(key)]; replaced {
			continue
		}
		env = append(env, entry)
	}
	for _, key := range slices.Sorted(maps.Keys(overrides)) {
		env = append(env, key+"="+overrides[key])
	}
	return env
}

// removeMeasureDir takes the measurement's directory away, waiting out the
// hive file's unlock the way the investigation says --rm must: a hive only
// just unloaded stays locked a moment past its last handle. It reports a
// directory it could not remove rather than failing on it.
func removeMeasureDir(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := os.RemoveAll(dir)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Logf("%s could not be removed and is left behind (%v); the account it belonged to is deleted", dir, err)
			return
		}
		time.Sleep(time.Second)
	}
}

// hiveMeasureName is the account this test builds and removes. Unmistakable
// on purpose, and spelled unlike any project account NameFor can derive.
const hiveMeasureName = Prefix + "hivemeasure"

// probeResult carries one probe's measurement: the exit code is the
// measurement, the captured words are the evidence.
type probeResult struct {
	exit int
	text string
}

// oneLine flattens a probe's captured output to one line for the report,
// cut short rather than left out: the words are the evidence.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}
