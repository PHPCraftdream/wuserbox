package group

import (
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// Delete removes a local group. Requires administrator rights.
func Delete(name string) error {
	r, _, _ := procDel.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))))
	return status("NetLocalGroupDel", r)
}
