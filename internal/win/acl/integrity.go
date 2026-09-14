package acl

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procGetSecurityDescriptorSacl = w32.Advapi32.NewProc("GetSecurityDescriptorSacl")

// labelInfo is LABEL_SECURITY_INFORMATION: the part of a security descriptor
// that holds the mandatory integrity label.
const labelInfo = 0x10

// ErrNotLabeled says the integrity label could not be written because this
// process does not hold the privilege for it. It is not a failure to report
// and give up on: the caller re-runs the work with administrator rights,
// which is where that privilege lives.
var ErrNotLabeled = errors.New("writing an integrity label needs administrator rights")

// canLabel is asked before every labeled update, and replaced in tests that
// have to cover both answers.
var canLabel = token.CanLabel

// CanLabelHere reports whether an integrity label can be written from this
// process, so a caller can tell a sandbox that will carry the boundary from
// one that will have to be repaired to get it.
func CanLabelHere() bool { return canLabel() }

// lowIntegritySACL builds a system access list carrying one mandatory label:
// Low, with the no-write-up policy, inherited the way the permission beside
// it is inherited.
//
// The descriptor is deliberately not freed. SetNamedSecurityInfo reads the
// list out of it during the call that follows, and freeing it first would
// hand Windows a pointer into memory already given back — the same tradeoff
// sid.Parse makes for an identifier kept for the life of the process.
func lowIntegritySACL(inheritance uint32) (uintptr, error) {
	text := fmt.Sprintf("S:(ML;%s;NW;;;LW)", sddlFlags(inheritance))

	var descriptor uintptr
	if r, _, err := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return 0, fmt.Errorf("building the integrity label: %w", err)
	}

	var present, defaulted int32
	var sacl uintptr
	if r, _, err := procGetSecurityDescriptorSacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return 0, fmt.Errorf("reading the integrity label: %w", err)
	}
	return sacl, nil
}

// sddlFlags spells inheritance the way a security descriptor's text form
// does. The label is inherited exactly as far as the permission it
// accompanies: a directory handed over whole labels what is inside it, while
// the profile root, which may only take new files, must not label the
// subdirectories it already has.
func sddlFlags(inheritance uint32) string {
	var b strings.Builder
	if inheritance&InheritObjects != 0 {
		b.WriteString("OI")
	}
	if inheritance&InheritContainers != 0 {
		b.WriteString("CI")
	}
	if inheritance&InheritNoPropagate != 0 {
		b.WriteString("NP")
	}
	if inheritance&InheritOnly != 0 {
		b.WriteString("IO")
	}
	return b.String()
}
