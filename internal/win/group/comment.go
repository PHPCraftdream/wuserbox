package group

import (
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// Comment returns the project directory recorded on the group, and whether the
// group exists at all.
func Comment(name string) (string, bool, error) {
	var buf *info1
	r, _, _ := procGetInfo.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))), 1, uintptr(unsafe.Pointer(&buf)))
	if r == errNotFound {
		return "", false, nil
	}
	if err := status("NetLocalGroupGetInfo", r); err != nil {
		return "", false, err
	}
	defer procFreeBuf.Call(uintptr(unsafe.Pointer(buf)))
	return w32.GoString(buf.comment), true, nil
}
