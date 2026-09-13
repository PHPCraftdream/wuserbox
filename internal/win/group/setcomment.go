package group

import (
	"unsafe"

	"wuserbox/internal/win/w32"
)

// SetComment rewrites the project directory recorded on an existing group.
// Requires administrator rights.
func SetComment(name, comment string) error {
	data := struct{ comment *uint16 }{w32.UTF16(comment)}
	var badParam uint32
	r, _, _ := procSetInfo.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))), 1002,
		uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&badParam)))
	return status("NetLocalGroupSetInfo", r)
}
