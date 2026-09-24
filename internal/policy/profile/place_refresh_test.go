package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestARespelledAnswerSurvivesARefreshWithoutAScan(t *testing.T) {
	if !fileSystemJoins(t, "q7", "Q7") {
		t.Skip("this volume holds q7 and Q7 apart, so there is no alias answer to keep")
	}

	probeRoots := make([]*os.Root, 2)
	probeResolvers := make([]*placeResolver, 2)
	for i := range probeResolvers {
		probeRoots[i], probeResolvers[i] = refreshedResolver(t)
		defer func(root *os.Root) { _ = root.Close() }(probeRoots[i])
	}
	probeScans := [2]int{probeResolvers[0].scans, probeResolvers[1].scans}
	probeMaps := [2]int{probeResolvers[0].canonicalMaps, probeResolvers[1].canonicalMaps}
	probeVisits := [2]int{probeResolvers[0].aliasChildVisits, probeResolvers[1].aliasChildVisits}

	// AllocsPerRun calls the closure once before measurement. Use a distinct
	// prepared resolver for each call so both resolve a genuinely new spelling.
	var probe placeResult
	nextProbe := 0
	probeAllocs := testing.AllocsPerRun(1, func() {
		probe = probeResolvers[nextProbe].place("Q7X")
		nextProbe++
	})
	if nextProbe != len(probeResolvers) {
		t.Fatalf("AllocsPerRun resolved the probe spelling %d times, want one warm-up and one measured resolution", nextProbe)
	}
	if !probe.ok || probe.canonical != "q7x" {
		t.Fatalf("first Q7X resolution after refresh was %+v, want the stored spelling q7x", probe)
	}
	if !sameEntryPlace(probeRoots[0], "Q7X", "q7x") {
		t.Fatal("a fresh resolver over the unchanged files does not resolve Q7X, so the fixture is broken")
	}
	for i, resolver := range probeResolvers {
		if resolver.scans != probeScans[i] || resolver.canonicalMaps != probeMaps[i] || resolver.aliasChildVisits != probeVisits[i] {
			t.Errorf("first Q7X resolution after refresh on resolver %d changed scans/maps/child visits by %d/%d/%d; want 0/0/0",
				i, resolver.scans-probeScans[i], resolver.canonicalMaps-probeMaps[i], resolver.aliasChildVisits-probeVisits[i])
		}
	}

	// The fresh control also gives the warm-up and measured call separate
	// resolvers, so each first spelling pays for its own sibling scan.
	freshRoots := make([]*os.Root, 2)
	freshResolvers := make([]*placeResolver, 2)
	for i := range freshResolvers {
		freshRoots[i], freshResolvers[i] = freshResolver(t)
		defer func(root *os.Root) { _ = root.Close() }(freshRoots[i])
	}
	freshScans := [2]int{freshResolvers[0].scans, freshResolvers[1].scans}
	freshMaps := [2]int{freshResolvers[0].canonicalMaps, freshResolvers[1].canonicalMaps}
	freshVisits := [2]int{freshResolvers[0].aliasChildVisits, freshResolvers[1].aliasChildVisits}
	nextFresh := 0
	freshAllocs := testing.AllocsPerRun(1, func() {
		freshResolvers[nextFresh].place("Q7X")
		nextFresh++
	})
	if nextFresh != len(freshResolvers) {
		t.Fatalf("AllocsPerRun resolved the fresh spelling %d times, want one warm-up and one measured resolution", nextFresh)
	}
	for i, resolver := range freshResolvers {
		if resolver.scans-freshScans[i] != 1 || resolver.canonicalMaps-freshMaps[i] != 8 || resolver.aliasChildVisits-freshVisits[i] != 8 {
			t.Errorf("first Q7X resolution on fresh resolver %d changed scans/maps/child visits by %d/%d/%d; want 1/8/8",
				i, resolver.scans-freshScans[i], resolver.canonicalMaps-freshMaps[i], resolver.aliasChildVisits-freshVisits[i])
		}
	}
	if probeAllocs >= freshAllocs/2 {
		t.Errorf("first resolution after refresh cost %.0f allocations and first fresh resolution cost %.0f; want refreshed cost below half",
			probeAllocs, freshAllocs)
	}
}

func refreshedResolver(t *testing.T) (*os.Root, *placeResolver) {
	t.Helper()
	dest := t.TempDir()
	names := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("q%d", i)
		write(t, filepath.Join(dest, name), "entry")
		names = append(names, name)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	index := newPlaceIndex(root, names)
	first := index.resolver.place("Q7")
	if !first.ok || first.canonical != "q7" || index.resolver.scans != 1 {
		_ = root.Close()
		t.Fatalf("initial alias question was answered %+v with %d scans; want q7 and one scan", first, index.resolver.scans)
	}
	if err := os.Rename(filepath.Join(dest, "q7"), filepath.Join(dest, "q7x")); err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	if err := index.refresh("q7x"); err != nil {
		_ = root.Close()
		t.Fatalf("refreshing the operation index after the mirror respelled the entry: %v", err)
	}
	return root, index.resolver
}

func freshResolver(t *testing.T) (*os.Root, *placeResolver) {
	t.Helper()
	dest := t.TempDir()
	for i := 0; i < 7; i++ {
		write(t, filepath.Join(dest, fmt.Sprintf("q%d", i)), "entry")
	}
	write(t, filepath.Join(dest, "q7x"), "entry")
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	return root, newPlaceResolver(root)
}
