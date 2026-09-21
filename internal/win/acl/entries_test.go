// The inherit-only half of the entries this package reads: an entry marked
// inherit-only never applies to the object it sits on, only to what it hands
// down to. --audit counted it both ways -- reporting a directory writable
// through a permission that only reaches what is created under it, and
// read-only through a refusal that only goes down -- while the directory
// itself answered the opposite. Both fixtures here ask the audit question
// and then put the answer against the file system itself, the way a sandbox
// would meet it: creating what the directory may or may not hold.

package acl

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// TestAnInheritOnlyPermissionDoesNotWriteTheDirectoryItSitsOn: a directory
// whose only entry is an (OI)(CI)(IO) permission for Everyone. The directory
// itself is not writable -- the entry passes it by -- while a directory under
// it is open through the copy it inherited, with the inherit-only mark taken
// off.
func TestAnInheritOnlyPermissionDoesNotWriteTheDirectoryItSitsOn(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	// The child is already there when the list lands, so the copy it
	// inherits is the one Windows pushes down -- without the inherit-only
	// mark.
	setSDDL(t, root, "D:P(A;OICIIO;FA;;;WD)")
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setSDDL(t, root, `D:P(A;OICI;FA;;;`+owner+`)`) })

	if EveryoneWritable(root) {
		t.Error("an inherit-only permission for Everyone was counted on the directory it sits on")
	}
	if !EveryoneWritable(child) {
		t.Error("the copy handed down to the child did not count as writable")
	}

	// The real thing the answer stands for: the directory itself holds
	// nothing new, the child does.
	if err := os.Mkdir(filepath.Join(root, "there"), 0o755); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("creating in the directory itself: %v, want permission refused", err)
	}
	if err := os.Mkdir(filepath.Join(child, "here"), 0o755); err != nil {
		t.Errorf("creating in the child through the inherited copy: %v", err)
	}
}

// TestAnInheritOnlyRefusalDoesNotTakeTheDirectoryItSitsOn: a directory with
// a real permission for Everyone and an (OI)(CI)(IO) refusal covering the
// changing rights beside it. The refusal goes down, not inward: the
// directory itself stays writable -- measured by creating inside it, which
// succeeds -- and the child, on which the refusal landed effective, does
// not.
func TestAnInheritOnlyRefusalDoesNotTakeTheDirectoryItSitsOn(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	// The refusal is spelled first: inherited copies keep their order, and a
	// refusal before a permission is how Windows reads a list anyway.
	setSDDL(t, root, fmt.Sprintf("D:P(D;OICIIO;0x%x;;;WD)(A;OICI;FA;;;WD)", changing))
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setSDDL(t, root, `D:P(A;OICI;FA;;;`+owner+`)`) })

	if !EveryoneWritable(root) {
		t.Error("an inherit-only refusal was counted on the directory it sits on")
	}
	if EveryoneWritable(child) {
		t.Error("the refusal handed down to the child did not count")
	}

	if err := os.Mkdir(filepath.Join(root, "there"), 0o755); err != nil {
		t.Errorf("creating in the directory itself: %v", err)
	}
	if err := os.Mkdir(filepath.Join(child, "here"), 0o755); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("creating in the child under the inherited refusal: %v, want permission refused", err)
	}
}
