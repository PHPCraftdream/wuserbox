package group

import (
	"unsafe"

	"wuserbox/internal/win/w32"
)

// Add creates a local group whose comment records the project directory.
// Requires administrator rights.
func Add(name, comment string) error {
	data := info1{name: w32.UTF16(name), comment: w32.UTF16(comment)}
	var badParam uint32
	r, _, _ := procAdd.Call(0, 1, uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&badParam)))
	return status("NetLocalGroupAdd", r)
}
