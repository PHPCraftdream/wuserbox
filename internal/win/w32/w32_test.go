package w32

import (
	"syscall"
	"testing"
	"unsafe"
)

func TestUTF16RoundTrip(t *testing.T) {
	for _, s := range []string{"", "C:\\tools", "путь", "a b c"} {
		if got := GoString(UTF16(s)); got != s {
			t.Errorf("round trip of %q gave %q", s, got)
		}
	}
}

func TestGoStringHandlesNil(t *testing.T) {
	if got := GoString(nil); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestLibrariesLoad(t *testing.T) {
	for name, dll := range map[string]*syscall.LazyDLL{
		"advapi32": Advapi32, "kernel32": Kernel32,
		"shell32": Shell32, "netapi32": Netapi32, "user32": User32,
	} {
		if err := dll.Load(); err != nil {
			t.Errorf("%s did not load: %v", name, err)
		}
	}
}

func TestFreeIgnoresNull(t *testing.T) {
	Free(0) // must not crash
	var x uint16
	_ = unsafe.Pointer(&x)
}
