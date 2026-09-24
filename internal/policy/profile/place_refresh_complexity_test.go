package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStructuralRefreshDoesNotVisitUnchangedAliasSiblings(t *testing.T) {
	for _, entries := range []int{4, 8} {
		t.Run(fmt.Sprintf("entries=%d", entries), func(t *testing.T) {
			unchanged := entries / 2
			paths := make([]string, 0, entries)
			for i := 0; i < unchanged; i++ {
				paths = append(paths, fmt.Sprintf("base-%d", i))
			}
			for i := 0; i < unchanged; i++ {
				paths = append(paths, fmt.Sprintf("new-%d", i))
			}

			dest := t.TempDir()
			for _, path := range paths[:unchanged] {
				write(t, filepath.Join(dest, path), "standing")
			}
			root, err := os.OpenRoot(dest)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			index := newPlaceIndex(root, paths)

			for _, path := range paths[unchanged:] {
				before := index.resolver.aliasChildVisits
				write(t, filepath.Join(dest, path), "created")
				if err := index.refresh(path); err != nil {
					t.Fatal(err)
				}
				if got := index.resolver.aliasChildVisits - before; got != 0 {
					t.Errorf("refreshing %s visited %d cached siblings, want none; B=%d unchanged siblings and M=%d sequential creations must not pay (M-1)*B visits", path, got, unchanged, unchanged)
				}

				fresh := newPlaceResolver(root)
				probes := append(append([]string(nil), paths...), "missing")
				for _, probe := range probes {
					for _, spelling := range []string{probe, strings.ToUpper(probe)} {
						got := index.resolver.place(spelling)
						want := fresh.place(spelling)
						if got.canonical != want.canonical || got.ok != want.ok || got.unknown != want.unknown {
							t.Errorf("place(%q) after refreshing %s = (%q, %t, %t), fresh resolver = (%q, %t, %t)", spelling, path, got.canonical, got.ok, got.unknown, want.canonical, want.ok, want.unknown)
						}
					}
				}
			}
			if got := index.resolver.aliasChildVisits; got > entries {
				t.Errorf("the %d-entry sequence visited %d cached children, want at most one linear sibling pass", entries, got)
			}
			snapshot := index.resolver.dirs["."]
			if !snapshot.canonicalComplete || len(snapshot.byCanonical) != entries {
				t.Errorf("the completed alias scan indexed %d canonical names with complete=%t, want %d and complete", len(snapshot.byCanonical), snapshot.canonicalComplete, entries)
			}
			if index.resolver.canonicalMaps != entries {
				t.Errorf("the resolver built %d canonical membership maps, want one per actual child", index.resolver.canonicalMaps)
			}
		})
	}
}
