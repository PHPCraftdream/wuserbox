package profile

import "os"

// Print is what one file looked like the last time a run carried it into a
// sandbox's profile: the source's size and its modification time, read to
// the nanosecond.
//
// Both numbers are the source's, and that is the whole point. The obvious
// fingerprint for "does this file still need copying" is taken from the
// destination, but the destination is the sandbox's to write, so its
// timestamps and its size are values the contained thing controls, and
// trusting either is trusting the sandbox. The source is never reachable
// from inside the sandbox, and the record of what it looked like lives
// outside the profile, beside the .copied list. Both halves of every
// comparison are then beyond the sandbox's reach, which is what makes
// skipping safe at all.
type Print struct {
	Size     int64
	ModNanos int64
}

// stillDescribes reports whether the source, as it sits on disk now, is
// still the file this print was taken from. Size and modification time
// together, no missing either: a same-size rewrite moves the modification
// time, and a touched-but-unchanged file keeps both, which is the boring
// answer wanted here.
func (p Print) stillDescribes(info os.FileInfo) bool {
	return p.Size == info.Size() && p.ModNanos == info.ModTime().UnixNano()
}
