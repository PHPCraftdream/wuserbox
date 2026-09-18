// Package sandbox ties identity, permissions and process launch together.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// Name maps a directory to its sandbox group name and returns the normalized
// directory it was derived from. The folder name keeps the group readable; the
// hash keeps it unique, since Windows group names are limited to 256 characters
// and paths are not.
func Name(dir string) (string, string, error) {
	// The same parser as every other path the commands take, so the project
	// directory can be written the same ways: a Windows path, the shell form,
	// a tilde or a variable all have to land on one sandbox.
	norm, err := paths.Resolve(dir)
	if err != nil {
		return "", "", err
	}
	// A Go Unicode fold is not the filesystem's case table: NTFS can keep
	// names such as K and the Kelvin sign apart. Existing paths therefore use
	// the spelling resolved by Windows itself; a missing path uses the
	// fail-safe ASCII-only fallback in pathid.Key.
	key, err := pathid.Key(norm)
	if err != nil {
		return "", "", err
	}
	// A disappeared project cannot be resolved to a filesystem entry. The
	// legacy group name is still a durable handle for its existing sandbox,
	// so check it before deriving a new identity key.
	legacyCandidates := legacyCandidates(norm, dir)
	for _, legacy := range legacyCandidates {
		if _, exists, err := group.Comment(legacy); err != nil {
			return "", "", err
		} else if exists {
			return legacy, norm, nil
		}
	}
	name := nameForKey(norm, key)
	// The key changed when filesystem identity replaced Unicode folding. Keep
	// an existing sandbox's group, account and record instead of silently
	// creating a second sandbox. Group comments are the durable mapping even
	// when the project itself has since disappeared.
	if existing, err := existingName(norm); err != nil {
		return "", "", err
	} else if existing != "" {
		name = existing
	}
	return name, norm, nil
}

func legacyCandidates(norm, original string) []string {
	var out []string
	add := func(path string) {
		name := legacyName(path)
		for _, prior := range out {
			if prior == name {
				return
			}
		}
		out = append(out, name)
	}
	add(norm)
	raw, err := filepath.Abs(filepath.Clean(strings.Trim(strings.TrimSpace(original), `"'`)))
	if err != nil {
		return out
	}
	add(raw)
	if parent, err := pathid.Canonical(filepath.Dir(raw)); err == nil {
		add(filepath.Join(parent, filepath.Base(raw)))
	}
	return out
}

func nameForKey(norm, key string) string {
	digest := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s%s-%s", group.Prefix, slug(filepath.Base(norm)), hex.EncodeToString(digest[:4]))
}

// legacyName is the identity used before filesystem-entry keys were adopted.
// It is retained for diagnostics and for callers that need to explain a
// migration, never as the identity for a new sandbox.
func legacyName(norm string) string {
	// This is the pre-pathid algorithm; keep Unicode lowercasing here solely
	// to find sandboxes created before the identity migration.
	digest := sha256.Sum256([]byte(strings.ToLower(norm)))
	return fmt.Sprintf("%s%s-%s", group.Prefix, slug(filepath.Base(norm)), hex.EncodeToString(digest[:4]))
}

func existingName(norm string) (string, error) {
	groups, err := group.List()
	if err != nil {
		return "", fmt.Errorf("cannot inspect existing sandboxes: %w", err)
	}
	var found string
	for _, entry := range groups {
		if entry.Dir == "" {
			continue
		}
		same, err := samePathIdentity(entry.Dir, norm)
		if err != nil {
			return "", err
		}
		if !same {
			continue
		}
		if found != "" && found != entry.Name {
			return "", fmt.Errorf("project %s belongs to multiple sandboxes (%s and %s); refusing to choose one", norm, found, entry.Name)
		}
		found = entry.Name
	}
	return found, nil
}

func samePathIdentity(first, second string) (bool, error) {
	a, err := pathid.Key(first)
	if err != nil {
		// Group enumeration is machine-wide: another user's sandbox may point
		// at a directory this process cannot inspect. It cannot be a verified
		// match, so ignore it unless its spelling is exactly the requested
		// path, in which case creating a second sandbox would be unsafe.
		if asciiFold(filepath.Clean(first)) == asciiFold(filepath.Clean(second)) {
			return false, fmt.Errorf("cannot verify existing sandbox path %s: %w", first, err)
		}
		return false, nil
	}
	b, err := pathid.Key(second)
	if err != nil {
		return false, fmt.Errorf("cannot verify requested sandbox path %s: %w", second, err)
	}
	return asciiFold(a) == asciiFold(b), nil
}

func asciiFold(path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, path)
}

// ProfileDir is where a sandbox's own thin profile lives, beside its temp
// directory under the state directory. A pure function of the group name,
// the same as Temp's own construction in build, so removal can compute it
// even from a record that is missing or damaged.
func ProfileDir(name string) string {
	return filepath.Join(paths.StateDir(), "profile", name)
}

// slug keeps a folder name to characters that are safe in a group name.
func slug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 32 {
		out = out[:32]
	}
	if out == "" {
		out = "root"
	}
	return out
}
