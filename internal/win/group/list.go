package group

import (
	"strings"
	"unsafe"

	"wuserbox/internal/win/w32"
)

// Entry is one sandbox group: its name and the directory it belongs to.
type Entry struct {
	Name string
	Dir  string
}

// List returns every local group created by wuserbox.
func List() ([]Entry, error) {
	var buf *info1
	var read, total uint32
	const maxPreferredLength = 0xFFFFFFFF
	r, _, _ := procEnum.Call(0, 1, uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), 0)
	if err := status("NetLocalGroupEnum", r); err != nil {
		return nil, err
	}
	defer procFreeBuf.Call(uintptr(unsafe.Pointer(buf)))
	var out []Entry
	for _, item := range unsafe.Slice(buf, read) {
		if name := w32.GoString(item.name); strings.HasPrefix(name, Prefix) {
			out = append(out, Entry{Name: name, Dir: w32.GoString(item.comment)})
		}
	}
	return out, nil
}
