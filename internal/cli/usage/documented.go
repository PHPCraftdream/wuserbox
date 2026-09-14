package usage

import (
	"flag"
	"sort"
	"strings"
)

// Mismatch compares the flags a command really registers against the ones its
// help entry lists, and returns what each side holds that the other does not:
// flags the command takes and the manual never mentions, and flags the manual
// offers that the command would reject.
//
// The options in Commands are written by hand, and nothing else stands between
// them and the flag sets they describe. A manual that claims to hold everything
// has to be held to that by something other than care.
//
// It is here rather than in a test because the flag sets are unexported, each
// in its own package, so the comparison has to be done from inside each of them.
func Mismatch(name string, flags *flag.FlagSet) (undocumented, missing []string) {
	listed, known := documented(name)
	if !known {
		return nil, nil
	}
	registered := map[string]bool{}
	flags.VisitAll(func(f *flag.Flag) { registered[f.Name] = true })

	for flagName := range registered {
		if !listed[flagName] {
			undocumented = append(undocumented, flagName)
		}
	}
	for flagName := range listed {
		if !registered[flagName] {
			missing = append(missing, flagName)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(missing)
	return undocumented, missing
}

// documented returns the flag names one entry lists, without their dashes.
func documented(name string) (map[string]bool, bool) {
	for _, command := range Commands {
		if command.Name != name {
			continue
		}
		listed := map[string]bool{}
		for _, option := range command.Options {
			// An option is written as "--dir <d>" or "--ro": the name is the
			// first word, and the dashes are not part of it.
			listed[strings.TrimLeft(strings.Fields(option.Name)[0], "-")] = true
		}
		return listed, true
	}
	return nil, false
}
