package sid

import (
	"fmt"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procConvertStringSidToSid = w32.Advapi32.NewProc("ConvertStringSidToSidW")

// Parse converts S-1-… text into a SID pointer owned by the system heap. The
// result stays valid for the life of the process and is never freed, because
// every caller keeps it for as long as it runs.
func Parse(text string) (uintptr, error) {
	var pointer uintptr
	if r, _, err := procConvertStringSidToSid.Call(uintptr(unsafe.Pointer(w32.UTF16(text))),
		uintptr(unsafe.Pointer(&pointer))); r == 0 {
		return 0, fmt.Errorf("%q is not a security identifier: %v", text, err)
	}
	return pointer, nil
}
