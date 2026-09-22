package account

import (
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// The identifier BuiltinUsersName parses is system memory for exactly as
// long as the name lookup runs, and the collector does not own it: asking
// the question several times in one process must not grow that memory by
// one identifier per question.
func TestBuiltinUsersNameGivesBackTheIdentifierItParses(t *testing.T) {
	parses, frees := sid.Parses(), sid.Frees()
	for i := 0; i < 5; i++ {
		if _, err := BuiltinUsersName(); err != nil {
			t.Fatalf("resolving the built-in Users alias: %v", err)
		}
	}
	if got := sid.Parses() - parses; got != 5 {
		t.Errorf("five questions parsed %d identifiers, want one each", got)
	}
	if got := sid.Frees() - frees; got != 5 {
		t.Errorf("five questions gave %d identifiers back, want all five parsed", got)
	}
}
