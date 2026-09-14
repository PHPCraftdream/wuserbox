package group

import (
	"strings"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// Entry is one sandbox group: its name and the directory it belongs to.
type Entry struct {
	Name string
	Dir  string
}

// IsSandbox reports whether a local group is one sandbox's own.
//
// Carrying the prefix is not enough. ReadGroup carries it too and is not a
// sandbox: it is one machine-wide group that lets every sandbox read the
// profile, and it belongs to no directory. Listing it offered a sandbox that
// --explain could not explain, --path could not place and --rm would not
// remove, on every machine that had ever run init.
func IsSandbox(name string) bool {
	return strings.HasPrefix(name, Prefix) && name != ReadGroup
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
		if name := w32.GoString(item.name); IsSandbox(name) {
			out = append(out, Entry{Name: name, Dir: w32.GoString(item.comment)})
		}
	}
	return out, nil
}
