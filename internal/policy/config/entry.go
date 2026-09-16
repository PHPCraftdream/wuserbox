package config

import "encoding/json"

// Entry is one item of the rules file's profile section: either a bare path,
// exactly what such an item has always meant, or the same path carrying
// limits on what gets copied under it.
//
// The two shapes share one type because the file holds both in one list, and
// a list of one shape cannot be widened into the other without a migration.
type Entry struct {
	Path string `json:"path"`
	// Depth is a pointer on purpose: the design gives "omitted" and "0"
	// different meanings -- omitted copies everything under the path, 0
	// copies only the files directly in it -- and an int cannot tell those
	// apart.
	Depth *int `json:"depth,omitempty"`
	// Include and Exclude are lists because one pattern cannot name two
	// extensions, and an agent keeping auth.json beside config.toml is the
	// ordinary case rather than the unusual one.
	Include []Mask `json:"include,omitempty"`
	Exclude []Mask `json:"exclude,omitempty"`
}

// Mask is one pattern in an entry's include or exclude list, with its own
// reach below the entry's path.
//
// The depth sits here as well as on the entry because one entry commonly
// wants both answers at once: the credentials at the top of an agent's
// directory, and the prompts wherever that agent has filed them. Without a
// depth per mask, somebody needing both has to name the same directory twice,
// as two entries that differ only in a number.
type Mask struct {
	Pattern string `json:"mask"`
	// Depth is a pointer for the same reason the entry's is: omitted falls
	// back to the entry's, and 0 means this mask matches only what sits
	// directly in the entry's path. An int would make those the same answer.
	Depth *int `json:"depth,omitempty"`
}

// MarshalJSON renders a mask as a bare string when it carries no depth of its
// own, so a list of plain patterns stays a list of plain patterns.
func (m Mask) MarshalJSON() ([]byte, error) {
	if m.Bare() {
		return json.Marshal(m.Pattern)
	}
	type plain Mask
	return json.Marshal(plain(m))
}

// UnmarshalJSON accepts a bare pattern or an object, the same two shapes an
// entry accepts, so there is one rule to learn about this file rather than
// two.
func (m *Mask) UnmarshalJSON(data []byte) error {
	var pattern string
	if err := json.Unmarshal(data, &pattern); err == nil {
		*m = Mask{Pattern: pattern}
		return nil
	}
	type plain Mask
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*m = Mask(p)
	return nil
}

// Bare reports whether the mask adds nothing to its pattern.
func (m Mask) Bare() bool { return m.Depth == nil }

// String is the pattern, so an error about a mask names what was written.
func (m Mask) String() string { return m.Pattern }

// DepthFor answers how far below the entry's path one of its masks reaches:
// the mask's own depth where it names one, and the entry's otherwise. Nil
// from either means no limit.
//
// It lives here rather than in the copier because it is a rule about what the
// file means, and the copier should be reading the answer rather than
// deciding it.
func (e Entry) DepthFor(m Mask) *int {
	if m.Depth != nil {
		return m.Depth
	}
	return e.Depth
}

// Masks wraps plain patterns, for callers holding a list of strings.
func Masks(patterns []string) []Mask {
	out := make([]Mask, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, Mask{Pattern: p})
	}
	return out
}

// MarshalJSON renders the entry as a bare JSON string when it carries no
// limits, and as an object when it does. ktav flattens through JSON on the
// way out, so this method is what decides which of the two shapes the file
// holds -- and it has to keep deciding for the bare shape, or every existing
// rules file would grow braces the first time wuserbox saved it.
func (e Entry) MarshalJSON() ([]byte, error) {
	if e.Bare() {
		return json.Marshal(e.Path)
	}
	// plain breaks the recursion: as Entry, this value would marshal through
	// this method again, and again, and never produce a byte.
	type plain Entry
	return json.Marshal(plain(e))
}

// UnmarshalJSON accepts either shape the file may hold: a bare string, which
// is every rules file written before limits existed, or an object. The string
// is tried first because it is the common case, and an object fails it
// cleanly, so nothing has to peek at the bytes to tell the two apart.
func (e *Entry) UnmarshalJSON(data []byte) error {
	var path string
	if err := json.Unmarshal(data, &path); err == nil {
		*e = Entry{Path: path}
		return nil
	}
	type plain Entry
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*e = Entry(p)
	return nil
}

// Bare reports whether the entry carries no limits at all, and so means
// exactly what a plain path in the rules file has always meant. It is what
// keeps the written file honest: an entry that says nothing new is written
// back as a bare string, not as an object repeating it. An empty mask list
// counts as no limits, because writing one would limp through the file
// saying nothing.
func (e Entry) Bare() bool {
	return e.Depth == nil && len(e.Include) == 0 && len(e.Exclude) == 0
}

// String is the path, so an error about an entry names the file it is about
// rather than a struct.
func (e Entry) String() string {
	return e.Path
}

// Entries wraps plain paths as bare entries, for callers that still hold the
// section as a list of strings -- the preset that pre-fills a fresh rules
// file, and anything else that has not learned the richer shape.
func Entries(paths []string) []Entry {
	out := make([]Entry, 0, len(paths))
	for _, p := range paths {
		out = append(out, Entry{Path: p})
	}
	return out
}
