package sid

import (
	"errors"
	"syscall"
	"testing"
	"unsafe"
)

// everyone builds the binary form of S-1-1-0 by hand, so the format tests
// need no account to resolve and no token to read.
func everyone() Value {
	return Value{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
}

// refusing stands in for ConvertSidToStringSidW with the one answer the real
// call cannot be made to give on demand: a plain refusal.
type refusing struct{ err error }

func (r refusing) Call(_ ...uintptr) (uintptr, uintptr, error) { return 0, 0, r.err }

// refuseTheConversion swaps the formatter's Windows call for one that fails
// with reason, and puts the real one back when the test is over.
func refuseTheConversion(t *testing.T, reason error) {
	t.Helper()
	real := procConvertSidToStringSid
	t.Cleanup(func() { procConvertSidToStringSid = real })
	procConvertSidToStringSid = refusing{err: reason}
}

// This pins the half of format's contract the empty-Value case cannot reach:
// a conversion Windows refuses comes back as an empty string AND a reason,
// with the errno it traveled with, never as a successful empty identity --
// which is what this used to be, folding every refusal into "" and no error.
func TestFormatKeepsTheReasonAConversionFailed(t *testing.T) {
	refuseTheConversion(t, syscall.Errno(8))
	value := everyone()
	text, err := format(unsafe.Pointer(&value[0]), value)
	if text != "" {
		t.Errorf("a refused conversion came back as %q", text)
	}
	if err == nil {
		t.Fatal("a refused conversion came back with no error")
	}
	if !errors.Is(err, syscall.Errno(8)) {
		t.Errorf("the refusal lost its reason: %v", err)
	}
}

// The same refusal seen from the caller that used to hand it out with a nil
// error: CurrentUser comes back with no text and the reason, not with an
// identity that merely looks empty.
func TestCurrentUserReportsARefusedConversion(t *testing.T) {
	refuseTheConversion(t, syscall.Errno(8))
	text, err := CurrentUser()
	if err == nil {
		t.Fatalf("a refused conversion came back with no error, text %q", text)
	}
	if text != "" {
		t.Errorf("a refused conversion came back as %q", text)
	}
	if !errors.Is(err, syscall.Errno(8)) {
		t.Errorf("the refusal lost its reason: %v", err)
	}
}

// The typed-pointer path against the real call, on bytes nobody resolved:
// the value itself is the owner the conversion holds, and it renders the
// same text its parsed form would.
func TestValueStringRendersBytesBuiltByHand(t *testing.T) {
	if got := everyone().String(); got != "S-1-1-0" {
		t.Errorf("S-1-1-0 rendered as %q", got)
	}
}
