// TestMain makes the synthetic world's promise for the whole binary: the
// sandbox SIDs these tests grant with are made up, so the operations they
// drive must treat them as identifiers that stand alone rather than as
// groups that have to exist (the fail-closed half of that contract is
// measured in the acl package, which never turns this on).

package access

import (
	"os"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

func TestMain(m *testing.M) {
	restore := grant.IdentitiesStandAloneForTest()
	code := m.Run()
	restore()
	os.Exit(code)
}
