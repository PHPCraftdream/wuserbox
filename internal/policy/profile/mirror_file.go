package profile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// openSource is the one place a copy's read of a source begins, and it is
// a variable for the same reason newPlaceResolver in place_resolver.go is: the
// window the ceiling's stale measurement lives in sits between the walk's
// os.Stat of a source and the open this is, and the test that pins that
// window has to be able to stand inside it and grow the file the walk
// already measured, the way the volume would if something wrote it
// between the two.
var openSource = os.Open

// scratchLen is the chunk a bounded copy reads through.
const scratchLen = 32 << 10

// newScratch is where a copy's scratch buffer is born, and it is a variable
// for the same reason openSource is: the test that pins one buffer to one
// copy operation has to be able to stand where the buffer is made and count.
var newScratch = func() []byte { return make([]byte, scratchLen) }

// mirrorFile carries one source file into its place at dst and answers with
// the print of the file it copied.
//
// charged is what the budget was debited for this file -- the walk's own
// measure of it -- and it does two jobs. It bounds the copy stream itself,
// because the ceiling counted a measurement and a stream bounded by nothing
// but that measurement is open to exactly what changed it: the walk Stat'ed
// the source, then this opens it, and something as ordinary as a program
// saving its own settings in between leaves this holding a file larger than
// the budget was ever told about. And it is the yardstick the opened source
// is held against when the copy starts -- more bytes under the name the walk
// measured than the walk measured is a different file than the one the run
// set out to move, and the copy refuses before the destination is touched,
// since carrying the larger file whole would be carrying past the ceiling
// and carrying it cut short would be writing a mixture nobody asked for.
// A re-Stat alone would answer neither question: what bounds a live stream
// is a check against the bytes as they go, not a second reading of the
// same measurement.
//
// The print comes from the opened handle rather than the walk's stale
// FileInfo, and it is earned only after the transfer is confirmed whole:
// the handle is re-Stat'ed once the bytes are down, and a size or a stamp
// that moved under the copy means what landed may be part of the file that
// was there and part of the one that replaced it. No print may claim a
// mixture -- a print is what lets a later run skip a copy, and skipping on
// the strength of bytes nobody can describe is how a stale copy outlives
// every correction.
//
// The bool this answers with says whether the destination's structure
// changed -- whether this call made a name that was not there, the file
// itself or a parent directory on the way to it. Rewriting the bytes of a
// file that already stood is not that: the name is where it was, the
// directory listings are what they were, and every canonical answer a
// resolver holds stays true. Where this call cannot rule a creation out it
// reports one, because a stretch carried across an unreported name is the
// one wrong direction this answer can take.
func mirrorFile(src, dst string, root *os.Root, charged int64, scratch *[]byte) (Print, bool, error) {
	var changed bool
	in, err := openSource(src)
	if err != nil {
		return Print{}, false, err
	}
	defer func() { _ = in.Close() }()
	// The opened handle's own measure, before anything else: this is the
	// size and the stamp the transfer will be asked to stand still for,
	// and the last reading taken before the destination is touched. The
	// walk's measure said what the budget was debited; this one says what
	// is actually here, and the two disagreeing is a source that changed
	// under the run, which is refused rather than carried.
	opened, err := in.Stat()
	if err != nil {
		return Print{}, false, err
	}
	if opened.Size() > charged {
		return Print{}, false, fmt.Errorf("%s measured %d bytes when the walk counted it and holds %d when the copy opened it, and a copy of the larger would not be the copy the budget was counted for: the source changed between the two readings, and the run refuses rather than carry what it never declared", src, charged, opened.Size())
	}
	if parent := filepath.Dir(dst); parent != "." {
		// MkdirAll below makes the name when nothing stands there, and
		// a name made is structure changed; asked here because
		// MkdirAll's own answer does not say whether it did anything.
		if _, readable := lookAt(root, parent); !readable {
			changed = true
		}
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return Print{}, false, err
		}
	}
	// os.Root pins the pathname, not the file object. A sandbox can leave a
	// link or reparse point in its profile, and O_TRUNC would then modify the
	// object reached through that name. In particular, a symlink to an
	// internal hard-link name can reach an external file while Lstat sees only
	// the symlink. Refuse links before opening the destination. A plain file
	// whose names all stay under this profile remains valid and is checked
	// below.
	if info, readable := lookAt(root, dst); readable {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return Print{}, false, fmt.Errorf("refusing to overwrite %s: destination is a symbolic link or reparse point", dst)
		}
		if info.Mode().IsRegular() {
			full := filepath.Join(root.Name(), filepath.FromSlash(dst))
			outside, err := pathid.OutsideNames(root.Name(), full)
			if err != nil {
				return Print{}, false, fmt.Errorf("checking destination %s for external hard links: %w", dst, err)
			}
			if len(outside) > 0 {
				return Print{}, false, fmt.Errorf("refusing to overwrite %s: it is also hard-linked outside the sandbox profile (%s)",
					dst, strings.Join(outside, ", "))
			}
		}
	} else {
		// O_CREATE below makes the name, and a name made is the
		// destination's structure changed. A file that stood here gets
		// its bytes rewritten under its own name, which is not:
		// truncating what a name holds leaves every listing and every
		// canonical answer as it was.
		changed = true
	}
	out, err := root.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return Print{}, false, err
	}
	// The first bytes actually to move are the first time this operation
	// pays for a buffer: a run whose every file is skipped by its print
	// never builds one. Built through the pointer the caller handed down,
	// so every file of the operation reads through the same buffer, and
	// never kept past the operation that owns it -- what the buffer holds
	// between files is fragments of the credential and settings files
	// this run carried in, and none of that outlives the copy.
	if *scratch == nil {
		*scratch = newScratch()
	}
	if _, err := copyBounded(out, in, charged, *scratch); err != nil {
		_ = out.Close()
		return Print{}, false, err
	}
	// The transfer is down, and the last thing it owes is proof the source
	// held still while it was read. What this catches is the same ordinary
	// writer the size check above catches, arrived through the door the
	// size check cannot close: a rewrite that keeps the size, or a write
	// that landed after the copy began. Either way the bytes in the
	// destination may be part of one file and part of another, and no
	// refusal here means no print means the next run copies the file
	// again -- which is the whole of what an uncertain copy can honestly
	// ask for.
	settled, err := in.Stat()
	if err != nil {
		_ = out.Close()
		return Print{}, false, err
	}
	if settled.Size() != opened.Size() || settled.ModTime().UnixNano() != opened.ModTime().UnixNano() {
		_ = out.Close()
		return Print{}, false, fmt.Errorf("%s held %d bytes stamped %d when the copy opened it and %d bytes stamped %d when it finished, and what was written may be part of the file that was there and part of the one that replaced it: the run refuses rather than record a print for the mixture", src, opened.Size(), opened.ModTime().UnixNano(), settled.Size(), settled.ModTime().UnixNano())
	}
	return Print{Size: opened.Size(), ModNanos: opened.ModTime().UnixNano()}, changed, out.Close()
}

// copyBounded copies in to out while the running total stays within limit,
// and refuses the moment the source offers a byte past it. The limit is the
// allocation the budget debited for this file -- the same charged the
// ceiling counted before the copy began -- and that is the whole reason the
// two have to be one number: a ceiling checked against a measurement, with
// a stream after it bounded by nothing, is a ceiling only for the files
// that sit still, and a source that grows between the walk and the copy
// would carry past it on the very pass that reported success. A stream that
// would exceed the limit is a source that changed under the run's
// measurement, and the refusal is the ceiling hole this exists to close.
// The chunk that would go past is never written, so what lands in the
// destination never holds more than the budget paid for, whatever the
// source does; what the source does with the rest is the next run's
// question, and the entry stays on the copied list to be cleared either
// way.
func copyBounded(out io.Writer, in io.Reader, limit int64, buf []byte) (int64, error) {
	// The scratch comes down from the caller -- one per copy operation,
	// not one per file -- but a caller handing none still gets the
	// standard chunk rather than a Read into a buffer of no length,
	// which would never end.
	if len(buf) == 0 {
		buf = newScratch()
	}
	var total int64
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if total+int64(n) > limit {
				return total, fmt.Errorf("the copy reached %d bytes of its %d-byte measure and the source still had more to give, which is a source that changed after it was measured: writing the rest would carry %d past what the budget was told of", total, limit, total+int64(n)-limit)
			}
			w, werr := out.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
			if w < n {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}
