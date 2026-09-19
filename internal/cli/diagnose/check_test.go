package diagnose

import (
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
)

// TestCheckRefusesWhatFollowsASeparator is the regression guard for a question
// that was silently replaced with another one: the flag package stops at a
// bare "--", nothing here read what it kept there, and "--check p --
// --operation read" checked write instead, with an exit code to match.
func TestCheckRefusesWhatFollowsASeparator(t *testing.T) {
	err := Check([]string{`C:\`, "--", "--operation", "read"})
	if err == nil {
		t.Fatal("what follows a \"--\" was accepted and dropped")
	}
	if got := exit.Of(err); got != exit.Usage {
		t.Errorf("got %v, want %v", got, exit.Usage)
	}
}
