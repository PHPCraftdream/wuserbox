// Package quietexec is the repository's one shared way to start a
// subprocess without any chance of a console window appearing on screen.
// Every *exec.Cmd it returns carries both process-creation settings that
// make that true, and the package's test observes, rather than assumes,
// that they do.
package quietexec

import (
	"os/exec"
	"syscall"
)

// createNoWindow is CREATE_NO_WINDOW: the child is given a console for
// which no window is ever created.
//
// The same constant lives, unexported, in internal/win/proc/job.go, which
// also records why it exists: a console-subsystem child started by a caller
// with no console gets a new console from Windows, and a new console comes
// with a window that appears and steals the focus. It is repeated here
// rather than imported because internal/win/proc would drag the job and
// token machinery into every package that only wants a quiet *exec.Cmd.
const createNoWindow = 0x08000000

// Command returns an *exec.Cmd for name and args that cannot put a console
// window on the screen. Both halves of that are set on SysProcAttr, because
// neither covers the other alone.
//
// CreationFlags carries CREATE_NO_WINDOW, which is what keeps a
// console-subsystem child from being handed a visible console when the
// caller has none: the window is never created at all, and GetConsoleWindow
// answers 0 on such a console -- measured in
// docs/investigations/2026-09-20-same-window-console.md, whose section 5
// launch-shape table records CREATE_NO_WINDOW leaving a hidden console of
// the child's own and whose section 4 probe output records GetConsoleWindow
// 0x0 for that shape.
//
// HideWindow is set as well because CREATE_NO_WINDOW says nothing about a
// GUI-subsystem child: its first ShowWindow would still be shown, and
// HideWindow is what suppresses that.
//
// The boundary of the contract, stated loudly because crossing it fails
// quietly: a child that must SHARE the caller's console -- inheriting it so
// console control events reach it, or writing to it -- must NOT start
// through this helper. CREATE_NO_WINDOW does not pass the caller's console
// on to the child; it hands the child a console of its own instead.
// Console-sharing runs are proc.Run and proc.RunWithConsole in
// internal/win/proc, the production paths that exist for exactly that.
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}
