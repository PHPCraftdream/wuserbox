// Package account manages the local user account that gives a sandbox an
// identity of its own, beside the group that already carries its
// permissions: made when the sandbox is, found again from that group by a
// plain computation rather than a table, and removed with it.
package account

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// Prefix marks local accounts wuserbox creates. It is group.Prefix and not
// one of its own, because there is only one local accounts database: a user
// and a group are different kinds of security principal to Windows, but
// NetUserAdd still refuses to create one with the same name as an existing
// group, so NameFor has to make the two spellings different regardless of
// which prefix either starts from.
const Prefix = group.Prefix

// hashLen is the width of the hex suffix sandbox.Name derives from a
// project's path: 4 bytes of a hash, hex-encoded.
const hashLen = 8

// NameFor derives a project's account name from its group name, the same
// way the group's own name derives from the project's directory: a plain
// computation, not a lookup, so nothing has to remember the pairing.
//
// It keeps only the group's trailing hash and drops the readable project
// slug in front of it. NetUserAdd caps a local account name at 20
// characters where NetLocalGroupAdd allows 256, so the group's full
// name -- prefix, slug and hash -- does not fit into an account name; the
// hash alone, already what keeps two projects from colliding as groups,
// fits with room to spare, and dropping the slug is what keeps the two
// names apart on every project whose slug is not empty, which is every one
// that reached slug() with a directory name to work from.
func NameFor(groupName string) string {
	if len(groupName) <= hashLen {
		return Prefix + groupName
	}
	return Prefix + groupName[len(groupName)-hashLen:]
}

// Own says whether name is an account wuserbox made: the prefix and exactly
// the hex suffix NameFor builds, nothing looser. An account somebody else
// happened to call wub-something is not one of ours, and this is asked in
// order to decide whether a process may raise its own privileges, which is
// not a question to answer on a prefix alone.
func Own(name string) bool {
	// Either case throughout, though NameFor only ever writes the lower one.
	// Windows compares account names without regard to case, so a name can
	// come back spelled otherwise; of the two ways to be wrong here, failing
	// to recognize a sandbox is the one that opens something, and refusing
	// an outsider who named themselves this way costs them nothing they had.
	if len(name) != len(Prefix)+hashLen || !strings.EqualFold(name[:len(Prefix)], Prefix) {
		return false
	}
	for _, r := range name[len(Prefix):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// InsideSandbox reports whether this process is one wuserbox started inside
// a sandbox. Two questions are asked, because there are two mechanisms: the
// account a sandbox now runs as, and the restricted token it used to.
//
// This replaces asking the kernel whether the token is restricted, which
// was the whole answer while a sandbox was the caller's own token cut down,
// and silently became no answer at all the moment a sandbox became an
// account instead -- IsTokenRestricted says false for an ordinary account,
// so a sandboxed process would have been allowed to ask for administrator
// rights and to run the commands that change other sandboxes.
//
// Neither question can be answered by the process being asked about. Who a
// process runs as is the kernel's to say, the same as the flag was.
func InsideSandbox() bool {
	if token.IsRestricted() {
		return true
	}
	current, err := sid.CurrentUser()
	if err != nil {
		return false
	}
	value, err := sid.Parse(current)
	if err != nil {
		return false
	}
	name, err := sid.Name(value)
	if err != nil {
		return false
	}
	return Own(name)
}

var (
	procUserAdd = w32.Netapi32.NewProc("NetUserAdd")
	procUserDel = w32.Netapi32.NewProc("NetUserDel")
	procFreeBuf = w32.Netapi32.NewProc("NetApiBufferFree")
)

// USER_INFO_1 flags and privilege level. UF_SCRIPT is required by
// NetUserAdd for every account, script or not. UF_DONT_EXPIRE_PASSWD is the
// one that matters here: nothing in this design ever rotates the password
// once CreateProcessWithLogonW starts relying on it existing unchanged on
// every run, so an expiry policy that locked the account out would strand
// every sandbox built under it.
const (
	ufScript           = 0x0001
	ufDontExpirePasswd = 0x10000
	userPrivUser       = 1
)

type userInfo1 struct {
	name        *uint16
	password    *uint16
	passwordAge uint32
	priv        uint32
	homeDir     *uint16
	comment     *uint16
	flags       uint32
	scriptPath  *uint16
}

// Add creates a local user account at the ordinary privilege level, with no
// home directory or logon script, and a password that never expires on its
// own. comment carries the project directory, the same as a sandbox's
// group. Requires administrator rights.
func Add(name, comment, password string) error {
	data := userInfo1{
		name:     w32.UTF16(name),
		password: w32.UTF16(password),
		priv:     userPrivUser,
		comment:  w32.UTF16(comment),
		flags:    ufScript | ufDontExpirePasswd,
	}
	var badParam uint32
	r, _, _ := procUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&badParam)))
	return status("NetUserAdd", r)
}

// Delete removes a local user account. Requires administrator rights.
func Delete(name string) error {
	r, _, _ := procUserDel.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))))
	return status("NetUserDel", r)
}

// status turns a NET_API_STATUS code shared by the NetUser and
// NetLocalGroup families into an error. 0 is success on every call in both
// families, and 5 is access denied on every one of them too; the rest are
// left as the bare number, the same as group.status does for the group
// calls this mirrors.
func status(call string, code uintptr) error {
	switch code {
	case 0:
		return nil
	case 5:
		return fmt.Errorf("%s: access denied (administrator required)", call)
	default:
		return fmt.Errorf("%s: NET_API_STATUS %d", call, code)
	}
}
