package config

// Strict reading of the user's rules file. Load decodes through
// encoding/json, which reads past any key it does not recognize: a rules
// file holding one is accepted, and the next Save writes the file back
// without the key and everything under it -- a typo'd key would vanish
// without a word the first time any command saved the rules. The typed
// decode cannot be asked about the keys it dropped, so the check re-parses
// the same bytes through ktav.Loads, which keeps them, and walks the
// untyped tree against the schema below.
//
// The file is refused as a whole, not trimmed around the problem: a command
// that loaded a file holding an unrecognized key and went on to save it --
// add-dir, remove-dir, and every run that rewrites its records -- would make
// the loss permanent. Refusing the file whole is also what the copier's
// contract for a file it cannot mean asks for, that the answer to "what did
// the run do with my file" is always "nothing, the file was refused".
//
// The typed decode remains the authority on types and shapes: this walk
// only answers the two questions encoding/json cannot -- is every key one
// this program knows, and does every path, directory and mask name
// something. Where a value is not the type the schema says, the walk steps
// around it and lets the typed decode's own error stand.

import (
	"fmt"
	"sort"
	"strings"

	ktav "github.com/ktav-lang/golang"
)

// The keys each object in the file may carry, kept beside the kinds of thing
// they belong to, so an unknown key can be named together with what would
// have been welcome in its place.
var (
	topKeys   = []string{"projects", "profile", "cleanup"}
	ruleKeys  = []string{"dir", "rw", "ro"}
	entryKeys = []string{"path", "depth", "include", "exclude"}
	maskKeys  = []string{"mask", "depth"}
)

// theFile is the location the top level is refused under, which has no
// section and no index to name.
const theFile = "the file"

// checkSource walks the untyped tree of the rules file against the schema
// above, refusing the file when it carries a key nothing here reads, or a
// directory, path or mask that names nothing.
//
// LoadsInto has already succeeded by the time this runs, so the type
// assertions below are belt and braces: on a shape the typed decode found
// surprising, the check steps around the value and lets the typed decode's
// own error stand, rather than inventing a refusal the typed decode would
// contradict. A key the schema requires may also be missing altogether, so an
// object that names no path, directory or pattern is refused the same way
// whether the key is absent or says nothing.
func checkSource(src string) error {
	doc, err := ktav.Loads(src)
	if err != nil {
		return err
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return fmt.Errorf("the file must hold projects, profile and cleanup, and it holds %T", doc)
	}
	if err := checkKeys(theFile, theFile, obj, topKeys); err != nil {
		return err
	}
	if err := checkProjects(obj["projects"]); err != nil {
		return err
	}
	if err := checkProfile(obj["profile"]); err != nil {
		return err
	}
	return checkCleanup(obj["cleanup"])
}

// checkProjects walks the projects section, one rule at a time.
func checkProjects(projects any) error {
	items, ok := projects.([]any)
	if !ok {
		return nil
	}
	for i, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		where := fmt.Sprintf("projects[%d]", i)
		if dir, ok := entry["dir"].(string); ok {
			where = fmt.Sprintf("projects[%d] (%s)", i, dir)
		}
		if err := checkKeys(where, "a projects entry", entry, ruleKeys); err != nil {
			return err
		}
		if dir, ok := entry["dir"].(string); !ok || namesNothing(dir) {
			return fmt.Errorf("projects[%d]: the rule names no directory -- %q is empty once its "+
				"quotes and spaces are gone, so no project can match it; name the directory the rule "+
				"is about", i, dir)
		}
		for _, list := range []string{"rw", "ro"} {
			members, ok := entry[list].([]any)
			if !ok {
				continue
			}
			for j, member := range members {
				dir, ok := member.(string)
				if !ok || !namesNothing(dir) {
					continue
				}
				return fmt.Errorf("projects[%d]: %s[%d] names no directory -- a grant for it would be "+
					"dropped without a word, so the file is refused instead; write the directory, or "+
					"remove the line", i, list, j)
			}
		}
	}
	return nil
}

// checkProfile walks the profile section, whose items are either a bare path
// or an object naming one and putting limits on what gets copied under it.
func checkProfile(profile any) error {
	items, ok := profile.([]any)
	if !ok {
		return nil
	}
	for i, item := range items {
		switch entry := item.(type) {
		case string:
			if !namesNothing(entry) {
				continue
			}
			return fmt.Errorf("profile[%d]: the entry names no path -- %q is empty once its quotes and "+
				"spaces are gone, and a run would either copy the profile root itself or skip the entry "+
				"without a word; name the file or directory inside the profile", i, entry)
		case map[string]any:
			where := fmt.Sprintf("profile[%d]", i)
			if path, ok := entry["path"].(string); ok {
				where = fmt.Sprintf("profile[%d] (%s)", i, path)
			}
			if err := checkKeys(where, "a profile entry", entry, entryKeys); err != nil {
				return err
			}
			if path, ok := entry["path"].(string); !ok || namesNothing(path) {
				return fmt.Errorf("profile[%d]: the entry names no path -- %q is empty once its quotes "+
					"and spaces are gone, and a run would either copy the profile root itself or skip "+
					"the entry without a word; name the file or directory inside the profile", i, path)
			}
			if depth, ok := entry["depth"].(int64); ok && depth < 0 {
				return fmt.Errorf("profile[%d]: depth is %d, and depths start at 0 -- 0 already keeps "+
					"only what sits directly in the path, so a negative depth reaches nothing and "+
					"copies nothing; write the depth you meant, or remove the line", i, depth)
			}
			for _, list := range []string{"include", "exclude"} {
				if err := checkMasks(entry[list], "profile[%d]: %s[%d]", i, list); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkMasks walks one entry's include or exclude list. The list is optional,
// and a member the typed decode will read as a mask is either the pattern
// itself or an object carrying the pattern and a depth of its own.
func checkMasks(masks any, where string, i int, list string) error {
	items, ok := masks.([]any)
	if !ok {
		return nil
	}
	for j, member := range items {
		at := fmt.Sprintf(where, i, list, j)
		switch mask := member.(type) {
		case string:
			if !namesNothing(mask) {
				continue
			}
			return fmt.Errorf("%s: names no pattern -- a mask with nothing in it matches no file, so it "+
				"protects nothing in an exclude list and copies nothing in an include one; write the "+
				"pattern, or remove it", at)
		case map[string]any:
			if err := checkKeys(at, "a mask", mask, maskKeys); err != nil {
				return err
			}
			if pattern, ok := mask["mask"].(string); !ok || namesNothing(pattern) {
				return fmt.Errorf("%s: the mask names no pattern -- a mask with nothing in it matches no "+
					"file, so it protects nothing in an exclude list and copies nothing in an include "+
					"one; write the pattern, or remove it", at)
			}
			if depth, ok := mask["depth"].(int64); ok && depth < 0 {
				return fmt.Errorf("%s: depth is %d, and depths start at 0 -- the mask reaches nothing, "+
					"so an include copies nothing and an exclude protects nothing; write the depth you "+
					"meant, or remove the mask", at, depth)
			}
		}
	}
	return nil
}

// checkCleanup walks the cleanup section, whose items are masks the same way
// an entry's lists are.
func checkCleanup(cleanup any) error {
	items, ok := cleanup.([]any)
	if !ok {
		return nil
	}
	for i, item := range items {
		switch mask := item.(type) {
		case string:
			if !namesNothing(mask) {
				continue
			}
			return fmt.Errorf("cleanup[%d]: the mask names no pattern -- a mask with nothing in it "+
				"matches no file, so it clears nothing; write the pattern, or remove it", i)
		case map[string]any:
			if err := checkKeys(fmt.Sprintf("cleanup[%d]", i), "a mask", mask, maskKeys); err != nil {
				return err
			}
			if pattern, ok := mask["mask"].(string); ok && namesNothing(pattern) {
				return fmt.Errorf("cleanup[%d]: the mask names no pattern -- a mask with nothing in it "+
					"matches no file, so it clears nothing; write the pattern, or remove it", i)
			}
			if depth, ok := mask["depth"].(int64); ok && depth < 0 {
				return fmt.Errorf("cleanup[%d]: depth is %d, and depths start at 0 -- the mask would "+
					"clear nothing, so whatever it was written to sweep stays; write the depth you "+
					"meant, or remove the mask", i, depth)
			}
		}
	}
	return nil
}

// checkKeys refuses the object when it carries a key the schema does not
// list. The object's keys are checked in sorted order, so the same file
// always earns the same refusal whichever order the map hands them over in.
func checkKeys(where, kind string, obj map[string]any, known []string) error {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		listed := false
		for _, k := range known {
			if k == key {
				listed = true
				break
			}
		}
		if listed {
			continue
		}
		head := fmt.Sprintf("%s: unknown key %q -- ", where, key)
		if where == theFile {
			head = fmt.Sprintf("unknown key %q at the top of the file -- ", key)
		}
		carried := strings.ToUpper(kind[:1]) + kind[1:] + " may carry " + strings.Join(known, ", ")
		if near, ok := nearestKey(known, key); ok {
			return fmt.Errorf("%sdid you mean %q? %s. Refusing the file rather than reading past %q, "+
				"because the next save would write it back without the key and whatever it was meant "+
				"to say", head, near, carried, key)
		}
		return fmt.Errorf("%s%s. Refusing the file rather than reading past %q, because the next save "+
			"would write it back without the key and whatever it was meant to say", head, carried, key)
	}
	return nil
}

// nearestKey names the known key a writer most plausibly meant, when one sits
// within a couple of edits of what they wrote. A typo'd key is the ordinary
// way this refusal fires, and naming the key the writer almost certainly
// meant turns the refusal into the fix -- "did you mean dir" instead of a
// schema to diff the file against by hand. When two known keys are equally
// near, the earlier one wins, so the same typo always earns the same answer.
func nearestKey(known []string, got string) (string, bool) {
	best := ""
	bestDistance := 0
	found := false
	for _, candidate := range known {
		distance := lev(candidate, got)
		if distance > 2 {
			continue
		}
		if !found || distance < bestDistance {
			best, bestDistance, found = candidate, distance, true
		}
	}
	return best, found
}

// lev is the Levenshtein distance between a and b: how many single-character
// inserts, deletes and substitutions turn one into the other. Schema keys are
// short ASCII words, so the classic table over bytes is everything the
// question needs.
func lev(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}

// namesNothing answers whether a directory, path or pattern, once its
// decoration is stripped, fails to name anything. The non-obvious part is
// that ktav reads "" not as an empty string but as a bare scalar holding the
// two quote characters, so a value that names nothing arrives wearing quotes
// or blanks, and the comparison strips both before calling it empty.
func namesNothing(value string) bool {
	return strings.TrimSpace(strings.Trim(value, "\"'")) == ""
}
