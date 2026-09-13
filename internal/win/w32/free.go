package w32

import "unsafe"

var procLocalFree = Kernel32.NewProc("LocalFree")

// Free releases a buffer that a Windows call allocated on the local heap.
func Free(p uintptr) {
	if p != 0 {
		procLocalFree.Call(p)
	}
}

var _ = unsafe.Pointer(nil)
