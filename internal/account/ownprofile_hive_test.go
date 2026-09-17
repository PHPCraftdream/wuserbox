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
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// TestWhereTheSeededHiveRefusesItsOwnAccount measures, where the rights
// are, the refusal docs/investigations/a-hive-per-slot.md recorded: the
// hive MakeProfile seeds is read-only for the account it was seeded for,
// while HKCU\Software\Classes -- which the profile service builds, not
// wuserbox -- accepts writes, and reads work. The cause is open, somewhere
// between RegLoadAppKey's empty hive and tightenHive's permission list;
// this test must not guess at a fix, only hand the next person the answer.
//
// The output is the finding, not the pass or fail: one logon per probe it
// asks reg.exe which writes the account's own hive accepts, then loads the
// hive and its UsrClass.dat to print, in words, who owns each key and what
// each permission list grants -- the key that refuses beside the key that
// accepts, so the difference is in the log and not in somebody's head.
//
// What it asserts is exactly what the transcript in the investigation
// already measured, and no more; the rest is reported, never asserted, so
// no guess can go red. When the picture changes the assertions below go
// red carrying the new report, and the investigation and docs/limits.md
// are the two things to update in the same change.
//
// It builds one real account and removes it, the lifecycle test's way, and
// needs administrator rights the same way; it says so when it skips.
func TestWhereTheSeededHiveRefusesItsOwnAccount(t *testing.T) {
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

	// What the measurement found, the first time it ran, on 2026-09-17. The
	// shape is the whole answer and each line is part of it: the account
	// reaches the root and everything it creates there itself, and reaches
	// nothing the first load created for it -- which is exactly a list
	// granted on the root and nowhere below it.
	//
	// Asserted rather than reported now, because reported facts do not
	// notice when they stop being true. Two of these go red the day the
	// defect is fixed, and that is what they are for: the fix is not
	// finished until this test, the hypothesis in
	// docs/investigations/a-hive-per-slot.md and the entry in
	// docs/limits.md are corrected in the same change, with the new
	// descriptors from the report above pasted into the investigation.
	for _, want := range []struct {
		at      int
		refused bool
		because string
	}{
		{0, true, "Software was created during the first load by somebody the tightened root names nothing about, so its own list does not name the account"},
		{1, false, "Software\\Classes is UsrClass.dat, and the profile service permissions its root to the account with entries that reach the subkeys"},
		{2, true, "the refusal is not about writing: the account cannot read Software either, which the investigation had recorded the other way round"},
		{3, false, "the root itself is where the tightened list grants the account everything, and the grant stops there"},
		{4, false, "a key the account creates under the root is the account's own, permissioned from its creator"},
		{5, false, "and stays the account's own, which is what makes the refusal above a matter of who made the key rather than of the hive being read-only"},
		{6, true, "Software refuses a value the same way it refuses a subkey"},
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

// describeSeededHive loads the seeded hive, then the profile service's own
// UsrClass.dat beside it, and prints the owner and permission list of the
// keys the probes wrote against. The seeded hive's own Software\Classes is
// a link into UsrClass.dat and does not open with the hive loaded alone,
// so the Classes write is described from that file's own root.
func describeSeededHive(t *testing.T, dir string) {
	for _, privilege := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
		if err := enablePrivilege(privilege); err != nil {
			t.Fatalf("the hives cannot be loaded to read their descriptors: %v", err)
		}
	}
	loadAndDescribe(t, filepath.Join(dir, "NTUSER.DAT"), "wub-hive-measure-%d", []keyLabel{
		{"", "the seeded hive's root (what HKCU was)"},
		{`Software`, `HKCU\Software`},
	})
	usrClass := filepath.Join(dir, `AppData\Local\Microsoft\Windows\UsrClass.dat`)
	if _, err := os.Stat(usrClass); err != nil {
		t.Logf("%s is not there (%v), so the key the probes' Classes write landed on cannot be described", usrClass, err)
		return
	}
	loadAndDescribe(t, usrClass, "wub-hive-usrclass-%d", []keyLabel{
		{"", "UsrClass.dat's root, which is what HKCU\\Software\\Classes resolved to during the probes"},
	})
}

type keyLabel struct{ rel, label string }

// loadAndDescribe loads one hive file under a per-process name, the way
// tightenHive names its own, and prints the keys named for it. A hive only
// just let go of a logon stays locked a moment, so the load waits; failing
// to load at all is fatal: a report with no descriptor in it is not a report.
func loadAndDescribe(t *testing.T, hive, nameFormat string, keys []keyLabel) {
	name := fmt.Sprintf(nameFormat, os.Getpid())
	loaded := false
	for try := 0; try < 20 && !loaded; try++ {
		if try > 0 {
			t.Logf("%s is still locked by the logon that just used it; waiting (%d of 20)", hive, try)
			time.Sleep(time.Second)
		}
		if r, _, _ := procRegLoadKey.Call(hkeyUsers,
			uintptr(unsafe.Pointer(w32.UTF16(name))),
			uintptr(unsafe.Pointer(w32.UTF16(hive)))); r == 0 {
			loaded = true
		}
	}
	if !loaded {
		t.Fatalf("%s never became loadable in 20 seconds, so its descriptors cannot be read", hive)
	}
	t.Cleanup(func() {
		procRegUnLoadKey.Call(hkeyUsers, uintptr(unsafe.Pointer(w32.UTF16(name))))
	})
	for _, k := range keys {
		path := name
		if k.rel != "" {
			path += `\` + k.rel
		}
		describeKey(t, path, k.label)
	}
}

// describeKey prints one key of the loaded hive: who owns it, and every
// entry of its permission list, in words a reader can act on. A key that
// refuses to open offline -- the seeded hive's link to UsrClass.dat, for
// one -- is reported as such, not treated as a broken rig.
func describeKey(t *testing.T, path, label string) {
	t.Helper()
	var key uintptr
	if r, _, _ := procRegOpenKeyEx.Call(hkeyUsers,
		uintptr(unsafe.Pointer(w32.UTF16(path))), 0, readControl,
		uintptr(unsafe.Pointer(&key))); r != 0 {
		t.Logf("  %s could not be opened to read its descriptor: error %d", label, r)
		return
	}
	defer procRegCloseKey.Call(key)

	// Owner, list and descriptor are three pointers into one buffer
	// Windows allocated, so they are held as pointers the whole way down
	// and narrowed to uintptr only where a call asks for one.
	var owner, dacl, sd unsafe.Pointer
	if r, _, _ := procGetSecurityInfo.Call(key, seRegistryKey,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)), 0,
		uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&sd))); r != 0 {
		t.Fatalf("reading the descriptor of %s failed: error %d", path, r)
	}
	defer w32.Free(uintptr(sd))

	who := "an identity that no longer resolves to a name"
	if name, err := sid.Name(uintptr(owner)); err == nil {
		who = name
	}
	if value, ok := sidValueAt(owner); ok {
		who = fmt.Sprintf("%s (%s)", who, value.String())
	}
	head := (*securityDescriptor)(sd)
	protection := "open to inherited entries"
	if head.control&daclProtectedControl != 0 {
		protection = "protected from inherited entries"
	}
	t.Logf("  %s -- owner %s, list %s:", label, who, protection)

	if head.control&daclPresentControl == 0 || dacl == nil {
		t.Logf("    no permission list to read")
		return
	}
	list := (*aclHeader)(dacl)
	where := unsafe.Add(dacl, unsafe.Sizeof(aclHeader{}))
	for i := 0; i < int(list.count); i++ {
		header := (*aceHeader)(where)
		if header.size == 0 {
			t.Logf("    entry %d has no size, so the walk stops before it lies", i+1)
			return
		}
		var kind string
		switch header.kind {
		case aceAccessAllowed:
			kind = "allow"
		case aceAccessDenied:
			kind = "deny"
		default:
			t.Logf("    entry %d is of a kind this reader does not know (type %d), so it is not paraphrased", i+1, header.kind)
			where = unsafe.Add(where, uintptr(header.size))
			continue
		}
		mask := *(*uint32)(unsafe.Add(where, 4))
		trustee := unsafe.Add(where, 8)
		who := "an identity that no longer resolves to a name"
		if name, err := sid.Name(uintptr(trustee)); err == nil {
			who = name
		}
		if value, ok := sidValueAt(trustee); ok {
			who = fmt.Sprintf("%s (%s)", who, value.String())
		}
		t.Logf("    %-5s %-32s %s -- %s", kind, who, accessWords(mask), inheritanceWords(header.flags))
		where = unsafe.Add(where, uintptr(header.size))
	}
}

// accessWords turns a registry access mask into words. The full
// KEY_ALL_ACCESS is spelled "all" because that is what the eye checks for;
// everything else is listed bit by bit, so nothing a descriptor says is
// paraphrased away.
func accessWords(mask uint32) string {
	const keyAllMask = 0xF003F
	if mask == keyAllMask {
		return "all"
	}
	var words []string
	for _, bit := range []struct {
		bit  uint32
		word string
	}{
		{0x000001, "query"},
		{0x000002, "set value"},
		{0x000004, "create subkey"},
		{0x000008, "enumerate"},
		{0x000010, "notify"},
		{0x000020, "create link"},
		{0x010000, "delete"},
		{0x020000, "read control"},
		{0x040000, "write dac"},
		{0x080000, "write owner"},
	} {
		if mask&bit.bit != 0 {
			words = append(words, bit.word)
		}
	}
	if len(words) == 0 {
		return "nothing"
	}
	return strings.Join(words, ", ")
}

// inheritanceWords says who an entry reaches and where it came from.
// Reaching subkeys is the one bit that decides whether a root's list
// protects anything below it, which is the question this file asks.
func inheritanceWords(flags byte) string {
	reach := "this key only"
	if flags&aceReachesSubkeys != 0 {
		reach = "this key and its subkeys"
	}
	switch {
	case flags&aceInherited != 0 && flags&aceInheritOnly != 0:
		return reach + ", inherited, inherit-only"
	case flags&aceInherited != 0:
		return reach + ", inherited"
	case flags&aceInheritOnly != 0:
		return reach + ", inherit-only"
	}
	return reach
}

var procGetSecurityInfo = w32.Advapi32.NewProc("GetSecurityInfo")

var procGetLengthSid = w32.Advapi32.NewProc("GetLengthSid")

// sidValueAt copies a SID out of a descriptor buffer into the package's
// own byte form, so Value.String can spell it; GetLengthSid is the only
// way to know how long a raw SID is.
func sidValueAt(pointer unsafe.Pointer) (sid.Value, bool) {
	if pointer == nil {
		return nil, false
	}
	length, _, _ := procGetLengthSid.Call(uintptr(pointer))
	if length == 0 || length > 68 {
		return nil, false
	}
	value := make(sid.Value, length)
	copy(value, unsafe.Slice((*byte)(pointer), length))
	return value, true
}

// The shapes GetSecurityInfo fills in and this file reads: a self-relative
// descriptor, the list header it points at, and the header every entry
// starts with. They mirror Windows' layouts byte for byte; nothing here
// builds one.
type securityDescriptor struct {
	revision byte
	sbz1     byte
	control  uint16
	owner    uint32
	group    uint32
	sacl     uint32
	dacl     uint32
}

type aclHeader struct {
	revision byte
	sbz1     byte
	size     uint16
	count    uint16
	sbz2     uint16
}

type aceHeader struct {
	kind  byte
	flags byte
	size  uint16
}

const (
	readControl              = 0x00020000
	seRegistryKey            = 4
	ownerSecurityInformation = 0x1
	daclSecurityInformation  = 0x4

	daclPresentControl   = 0x0004
	daclProtectedControl = 0x1000

	aceAccessAllowed = 0
	aceAccessDenied  = 1

	aceReachesSubkeys = 0x2 // CONTAINER_INHERIT_ACE: the entry reaches subkeys
	aceInheritOnly    = 0x8
	aceInherited      = 0x10
)

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
