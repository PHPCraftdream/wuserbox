package facts

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/profile"
)

// PrintsList is where the fingerprints of the last copy are kept: beside the
// .copied record, in the same directory of bookkeeping, and deliberately not
// inside the profile they describe. The skip they buy is safe only while
// both halves of the comparison are beyond the sandbox's reach. The numbers
// are the source's, but a record kept in the profile would be the sandbox's
// to edit, and a fingerprint the sandbox can lower is a copy it can keep
// past its own refresh.
func PrintsList(name string) string {
	return filepath.Join(paths.StateDir(), "tmp", name+".prints")
}

// Prints reads them back, keyed by each file's path inside the destination
// profile, spelled with forward slashes.
//
// Any problem reading the file means no fingerprints at all, and is not an
// error: a missing file is a sandbox never filled or filled by a version
// that kept no prints, a malformed line or a number that does not parse is
// a record nothing wrote. Every one of them answers an empty map, which
// sends the run down the same path as a first run -- copy everything, ask
// nothing. A cache must never be the reason something is skipped that
// should not have been, so every failure falls to the safe side, and the
// safe side is the more expensive one.
func Prints(name string) (map[string]profile.Print, error) {
	raw, err := os.ReadFile(PrintsList(name))
	if err == nil {
		if prints, parsed := parsePrints(raw); parsed {
			return prints, nil
		}
	}
	return map[string]profile.Print{}, nil
}

// parsePrints takes the file's lines -- `<size> <modnanos> <path>`, the path
// last so a path carrying a space needs no quoting -- and reports whether
// the whole file is any good. One bad line is one bad record: the file is
// discarded whole rather than the line skipped, because a fingerprint is
// only worth what the weakest entry in the record can be trusted for, and
// half a cache is a cache that sometimes lies.
func parsePrints(raw []byte) (map[string]profile.Print, bool) {
	prints := make(map[string]profile.Print)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			return nil, false
		}
		size, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, false
		}
		modnanos, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, false
		}
		prints[parts[2]] = profile.Print{Size: size, ModNanos: modnanos}
	}
	return prints, true
}

// RecordPrints writes them back, one line per file, sorted by path so the
// same profile writes the same bytes however the map chose to iterate. An
// empty map writes an empty file, which reads back as nothing known -- the
// state a --no-ai run leaves behind after taking a profile back.
func RecordPrints(name string, prints map[string]profile.Print) error {
	path := PrintsList(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var text string
	if len(prints) > 0 {
		keys := make([]string, 0, len(prints))
		for key := range prints {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var lines strings.Builder
		for _, key := range keys {
			print := prints[key]
			fmt.Fprintf(&lines, "%d %d %s\n", print.Size, print.ModNanos, key)
		}
		text = lines.String()
	}
	return os.WriteFile(path, []byte(text), 0o644)
}
