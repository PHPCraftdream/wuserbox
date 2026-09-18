// Group membership: making an account the sole member of its own sandbox
// group and of the two shared groups that let it read anything at all, and
// finding it again afterwards by asking the group who its member is.

package account

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procAddMembers = w32.Netapi32.NewProc("NetLocalGroupAddMembers")
	procGetMembers = w32.Netapi32.NewProc("NetLocalGroupGetMembers")
	procDelMembers = w32.Netapi32.NewProc("NetLocalGroupDelMembers")
)

type memberInfo3 struct {
	domainAndName *uint16
}

// These are what NetLocalGroupAddMembers and NetLocalGroupDelMembers report
// instead of success for the case each call treats as a no-op: adding a
// member that is already there, or removing one that never was.
const (
	errMemberInAlias    = 1378 // ERROR_MEMBER_IN_ALIAS
	errMemberNotInAlias = 1377 // ERROR_MEMBER_NOT_IN_ALIAS
)

// AddMember makes account a member of the local group named groupName.
// Already being a member is not an error: a run that got partway through
// this before being interrupted must be resumable by running it again, not
// stopped by its own earlier success. Requires administrator rights.
func AddMember(groupName, account string) error {
	entry := memberInfo3{domainAndName: w32.UTF16(account)}
	r, _, _ := procAddMembers.Call(0, uintptr(unsafe.Pointer(w32.UTF16(groupName))), 3,
		uintptr(unsafe.Pointer(&entry)), 1)
	if r == errMemberInAlias {
		return nil
	}
	return status("NetLocalGroupAddMembers", r)
}

// RemoveMember takes account out of the local group named groupName. Not
// being a member already is not an error, for the same reason it is not one
// in AddMember. Requires administrator rights.
func RemoveMember(groupName, account string) error {
	entry := memberInfo3{domainAndName: w32.UTF16(account)}
	r, _, _ := procDelMembers.Call(0, uintptr(unsafe.Pointer(w32.UTF16(groupName))), 3,
		uintptr(unsafe.Pointer(&entry)), 1)
	if r == errMemberNotInAlias {
		return nil
	}
	return status("NetLocalGroupDelMembers", r)
}

// EnsureMembership adds name to every group given, in order, stopping at
// the first one that fails so the caller knows which membership is still
// missing.
func EnsureMembership(name string, groups ...string) error {
	for _, g := range groups {
		if err := AddMember(g, name); err != nil {
			return err
		}
	}
	return nil
}

// Members lists the plain account names belonging to a local group, with
// the computer name Windows prefixes them with taken off. This is how a
// sandbox account is found again from its group -- the same way the group
// itself is found from its directory, by asking rather than by a table.
func Members(groupName string) ([]string, error) {
	var buf *memberInfo3
	var read, total uint32
	const maxPreferredLength = 0xFFFFFFFF
	r, _, _ := procGetMembers.Call(0, uintptr(unsafe.Pointer(w32.UTF16(groupName))), 3,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), 0)
	if err := status("NetLocalGroupGetMembers", r); err != nil {
		return nil, err
	}
	defer procFreeBuf.Call(uintptr(unsafe.Pointer(buf)))
	out := make([]string, 0, read)
	for _, item := range unsafe.Slice(buf, read) {
		out = append(out, bareName(w32.GoString(item.domainAndName)))
	}
	return out, nil
}

// BelongsTo proves that account is the account for groupName and project.
// Membership alone is not enough: a short legacy account name can collide
// with another sandbox, and deleting that account would destroy the other
// sandbox. The project comment is the second, durable identity check.
func BelongsTo(account, groupName, project string) (bool, error) {
	members, err := Members(groupName)
	if err != nil {
		return false, fmt.Errorf("cannot inspect membership of %s: %w", groupName, err)
	}
	found := false
	for _, member := range members {
		if strings.EqualFold(member, account) {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	comment, exists, err := Comment(account)
	if err != nil {
		return false, err
	}
	if !exists || comment == "" || project == "" {
		return false, nil
	}
	if same, err := pathid.Same(comment, project); err == nil {
		return same, nil
	}
	return asciiFold(filepath.Clean(comment)) == asciiFold(filepath.Clean(project)), nil
}

func asciiFold(path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, path)
}

// bareName drops the "COMPUTERNAME\" Windows always puts in front of a
// local account in a membership listing.
func bareName(name string) string {
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// BuiltinUsersName resolves BUILTIN\Users to the bare alias name
// NetLocalGroupAddMembers needs to add a member to it, because that name is
// only ever spelled "Users" on an English-language install: everywhere
// else Windows localizes it, the same reason every other well-known
// identity in this codebase is carried as a SID rather than a name.
func BuiltinUsersName() (string, error) {
	pointer, err := sid.Parse(sid.Users)
	if err != nil {
		return "", err
	}
	return sid.Name(pointer)
}
