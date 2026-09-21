package sid

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procConvertStringSidToSid = w32.Advapi32.NewProc("ConvertStringSidToSidW")

// Parse converts S-1-… text into a SID pointer owned by the system heap. The
// result stays valid until it is handed to Free. Most callers hold a parsed
// identifier for as long as the process runs and never free it; one whose
// identifier has a bounded lifetime -- a single pass over a tree -- frees it
// once the pass is over and nothing can reach the pointer any more.
func Parse(text string) (uintptr, error) {
	var pointer uintptr
	if r, _, err := procConvertStringSidToSid.Call(uintptr(unsafe.Pointer(w32.UTF16(text))),
		uintptr(unsafe.Pointer(&pointer))); r == 0 {
		return 0, fmt.Errorf("%q is not a security identifier: %w", text, err)
	}
	return pointer, nil
}

// Free returns a system-heap SID to Windows. Unlike a Go value, its lifetime
// is not the collector's to mind: freeing a pointer something still compares
// against is use of freed memory, so this belongs to the owner of the
// lifetime, and to nobody else.
func Free(pointer uintptr) {
	if pointer != 0 {
		w32.Free(pointer)
	}
}
