package sandbox

import (
	"strings"
	"testing"
)

// TestArgsCarriesTheDashThatMarksACommand is the regression guard for a
// rebuilt command line that named the command but not as one. Elevate re-runs
// wuserbox with these arguments as a brand new process, and a first word
// without a dash is read as a program to run, not as init: the elevated copy
// would have gone looking for a program called "init" instead of building the
// sandbox.
func TestArgsCarriesTheDashThatMarksACommand(t *testing.T) {
	args := Options{Dir: `C:\project`, RW: []string{`C:\extra`}, NoAI: true}.Args()
	if len(args) == 0 || args[0] != "--init" {
		t.Fatalf("the command line starts with %q, want \"--init\"", args)
	}
	if !strings.Contains(strings.Join(args, " "), `--dir C:\project`) {
		t.Errorf("the project directory is missing: %v", args)
	}
}
