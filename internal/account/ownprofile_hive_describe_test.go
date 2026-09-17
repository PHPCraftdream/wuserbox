package account

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

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
