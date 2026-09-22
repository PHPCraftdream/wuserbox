// The promise a grant operation is handed about the account it acts for.

package grant

import (
	"sync/atomic"

	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// testIdentifiersStandAlone is the synthetic world's promise, made by the
// test binaries that drive this package with sandbox SIDs they made up:
// every account handed over is an identifier that names nothing beyond
// itself. Production leaves it false, and nothing outside the test
// binaries calls the function that sets it.
var testIdentifiersStandAlone atomic.Bool

// identityOf hands the account to the acl operation under the promise the
// caller's world has made about it. A production run is always handed the
// sandbox's own group, which exists, so every lookup about it must answer:
// a grant or a revoke that Windows cannot fully resolve -- NoneMapped
// included, which a name resolution that ran out of time also answers --
// stops before it touches anything. A test binary that made its sandbox
// SIDs up has promised the opposite, and gets the answer its fixtures
// have always stood on.
func identityOf(account string) acl.Identity {
	if testIdentifiersStandAlone.Load() {
		return acl.IdentifierAlone(account)
	}
	return acl.SandboxGroup(account)
}

// IdentitiesStandAloneForTest makes the synthetic world's promise for as
// long as the caller keeps the returned restore: every account this
// package is handed is treated as an identifier that stands alone, never
// as a group that has to exist. It exists for the test binaries that
// drive the whole grant stack with made-up sandbox SIDs, the way the
// fixtures inside the acl package do; an acl caller makes the same
// promise directly, with acl.IdentifierAlone. Production code never calls
// this, and the tests that measure the fail-closed half of the contract
// live in the acl package, where no test turns it on.
func IdentitiesStandAloneForTest() (restore func()) {
	testIdentifiersStandAlone.Store(true)
	return func() { testIdentifiersStandAlone.Store(false) }
}
