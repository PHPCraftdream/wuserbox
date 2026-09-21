package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// warmTree builds the destination both dedupe benchmarks measure: sixteen
// top directories, each holding ten files and one subdirectory of five, so
// thirty-two entries of depth two over thirty-three directories -- the shape
// of a rules file already copied once. The review of 2026-09-20 (P2-5) found
// the dedupe costing more for every entry the record named even where no
// byte had changed, and this tree is that bill in a form a benchmark can
// hold still.
func warmTree(b *testing.B) string {
	dest := b.TempDir()
	for top := 0; top < 16; top++ {
		name := fmt.Sprintf("entry-%02d", top)
		topDir := filepath.Join(dest, name)
		if err := os.MkdirAll(topDir, 0o755); err != nil {
			b.Fatal(err)
		}
		for file := 0; file < 10; file++ {
			if err := os.WriteFile(filepath.Join(topDir, fmt.Sprintf("file-%02d.txt", file)), []byte("x"), 0o644); err != nil {
				b.Fatal(err)
			}
		}
		subDir := filepath.Join(topDir, "sub")
		if err := os.MkdirAll(subDir, 0o755); err != nil {
			b.Fatal(err)
		}
		for file := 0; file < 5; file++ {
			if err := os.WriteFile(filepath.Join(subDir, fmt.Sprintf("file-%02d.txt", file)), []byte("x"), 0o644); err != nil {
				b.Fatal(err)
			}
		}
	}
	return dest
}

// warmEntries names what warmTree built, top entry and its subdirectory
// side by side, the order a record comes back in.
func warmEntries() []config.Entry {
	entries := make([]config.Entry, 0, 32)
	for top := 0; top < 16; top++ {
		name := fmt.Sprintf("entry-%02d", top)
		entries = append(entries, config.Entry{Path: name}, config.Entry{Path: name + "/sub"})
	}
	return entries
}

// BenchmarkDedupeEntries measures one dedupe of the warm record over the
// warm tree: the work an already-copied profile pays on every copy before a
// single byte moves, which is the cost the review said grew with the square
// of the entries named.
func BenchmarkDedupeEntries(b *testing.B) {
	dest := warmTree(b)
	entries := warmEntries()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DedupeEntries(dest, entries)
	}
	b.ReportAllocs()
}
