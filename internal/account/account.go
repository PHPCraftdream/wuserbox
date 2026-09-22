// Package account manages the local user account that gives a sandbox an
// identity of its own, beside the group that already carries its
// permissions: made when the sandbox is, found again from that group by a
// plain computation rather than a table, and removed with it.
package account

import (
	"crypto/sha256"
	"encoding/hex"
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

// hashLen is the width of the legacy hex suffix sandbox.Name derived from a
// project's path: 4 bytes of a hash, hex-encoded.
const hashLen = 8

// accountHashLen is the width of the current account identity. The local
// account limit is twenty characters, so the prefix plus sixteen hex digits
// fits exactly and leaves enough identity bits to make equal legacy suffixes
// harmless.
const accountHashLen = 16

// NameFor derives a project's account name from its group name, the same
// way the group's own name derives from the project's directory: a plain
// computation, not a lookup, so nothing has to remember the pairing.
//
// NetUserAdd caps a local account name at 20 characters where
// NetLocalGroupAdd allows 256. The account therefore carries eight fresh
// hex digits derived from the complete group name plus the group's existing
// eight-digit suffix. The latter keeps the name explainable and preserves the
// old suffix convention; the former prevents two different group names with
// the same suffix from sharing an account.
func NameFor(groupName string) string {
	if len(groupName) <= hashLen {
		return Prefix + groupName
	}
	digest := sha256.Sum256([]byte(strings.ToLower(groupName)))
	return Prefix + hex.EncodeToString(digest[:4]) + groupName[len(groupName)-hashLen:]
}

// LegacyNameFor is the account spelling used before account identities grew
// to 64 bits. It is kept solely to find and remove an existing sandbox during
// migration; callers must verify that the account actually belongs to the
// requested group before acting on it.
func LegacyNameFor(groupName string) string {
	if len(groupName) <= hashLen {
		return Prefix + groupName
	}
	return Prefix + groupName[len(groupName)-hashLen:]
}

// Candidates returns current and legacy names, without duplicates.
func Candidates(groupName string) []string {
	current := NameFor(groupName)
	legacy := LegacyNameFor(groupName)
	if current == legacy {
		return []string{current}
	}
	return []string{current, legacy}
}

// Own says whether name has one of the account shapes wuserbox made: the
// prefix and either the current or legacy hex suffix. An account somebody
// else happened to call wub-something is not one of ours, and this is asked
// to decide whether a process may raise its own privileges, which is not a
// question to answer on a prefix alone.
func Own(name string) bool {
	// Either case throughout, though NameFor only ever writes the lower one.
	// Windows compares account names without regard to case, so a name can
	// come back spelled otherwise; of the two ways to be wrong here, failing
	// to recognize a sandbox is the one that opens something, and refusing
	// an outsider who named themselves this way costs them nothing they had.
	if len(name) < len(Prefix) || !strings.EqualFold(name[:len(Prefix)], Prefix) ||
		(len(name) != len(Prefix)+hashLen && len(name) != len(Prefix)+accountHashLen) {
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
// process runs as is the kernel's to say, the same as the flag was. When
// the kernel's answer cannot be read at all -- the lookup fails, the string
// does not parse -- the question is decided the way that refuses: both
// callers take yes to mean "do not elevate, do not touch permissions", and
// a failure read as "not a sandbox" would open exactly those to a process
// whose identity nothing established.
func InsideSandbox() bool {
	if token.IsRestricted() {
		return true
	}
	current, err := sid.CurrentUser()
	if err != nil {
		return true
	}
	value, err := sid.Parse(current)
	if err != nil {
		return true
	}
	defer sid.Free(value)
	name, err := sid.Name(value)
	if err != nil {
		return true
	}
	return Own(name)
}

var (
	procUserAdd     = w32.Netapi32.NewProc("NetUserAdd")
	procUserDel     = w32.Netapi32.NewProc("NetUserDel")
	procUserGetInfo = w32.Netapi32.NewProc("NetUserGetInfo")
	procFreeBuf     = w32.Netapi32.NewProc("NetApiBufferFree")
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

// Comment returns the project directory recorded on an account, and whether
// the account exists. The comment is part of the identity check: a colliding
// account name must never be treated as belonging to a different sandbox.
func Comment(name string) (string, bool, error) {
	var buf *userInfo1
	r, _, _ := procUserGetInfo.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))), 1,
		uintptr(unsafe.Pointer(&buf)))
	if r == 2221 { // NERR_UserNotFound
		return "", false, nil
	}
	if err := status("NetUserGetInfo", r); err != nil {
		return "", false, err
	}
	defer procFreeBuf.Call(uintptr(unsafe.Pointer(buf)))
	return w32.GoString(buf.comment), true, nil
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
