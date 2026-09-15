package proc

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procCreateProcessWithLogon = w32.Advapi32.NewProc("CreateProcessWithLogonW")

const (
	// logonWithProfile loads the account's profile before the process
	// starts. Without it there is no HKEY_CURRENT_USER at all for the
	// process to write into -- measured, see
	// docs/design/an-account-of-its-own.md.
	logonWithProfile = 0x00000001
	// The environment below is built by hand rather than inherited, so it
	// has to be marked wide or Windows reads the block as the ANSI form
	// CreateProcessA callers pass.
	createUnicodeEnvironment = 0x00000400
	// local is the domain that makes CreateProcessWithLogonW look the
	// account up in this machine's own SAM rather than, on a domain-joined
	// machine, the domain the caller happens to be logged into -- where a
	// same-named account may not exist, or may be a different one.
	local = "."
)

// RunAsAccount starts commandLine logged on as a local account, in the same
// job object and with the same interrupt handling as Run, but through
// CreateProcessWithLogonW rather than a token this process already holds.
//
// That is the one launch call documented to succeed from an ordinary user
// account without SE_TCB_NAME or "act as part of the operating system" --
// measured, see docs/design/an-account-of-its-own.md -- which is why
// starting a sandbox's own account needs no administrator rights on every
// run, only on init, the same as starting one under a restricted copy of
// the caller's own token used to.
//
// env replaces whatever this process would otherwise hand the child, rather
// than letting it inherit wuserbox's own variables and overriding a few of
// them afterwards, which would leave everything not overridden pointing at
// the caller's environment still.
func RunAsAccount(username, password, commandLine, directory string, env []string) (int, error) {
	j, err := newJob()
	if err != nil {
		return -1, err
	}
	defer j.Close()

	var startup syscall.StartupInfo
	var created syscall.ProcessInformation
	startup.Cb = uint32(unsafe.Sizeof(startup))
	line, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		return -1, err
	}
	block, err := environmentBlock(env)
	if err != nil {
		return -1, err
	}
	secret, err := syscall.UTF16FromString(password)
	if err != nil {
		return -1, err
	}
	// The password has to exist in memory in the form Windows reads, and
	// this is the only copy wuserbox makes of it. Cleared the moment the
	// call is done with it rather than left for the collector, which would
	// leave it lying in a freed page for as long as that page went unused.
	defer clear(secret)

	user, domain, cwd := w32.UTF16(username), w32.UTF16(local), w32.UTF16(directory)
	// Suspended, for the same reason Run starts its own child suspended:
	// nothing it starts can slip out before it is assigned to the job.
	const flags = createSuspended | createUnicodeEnvironment
	r, _, callErr := procCreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(&secret[0])), logonWithProfile,
		0, uintptr(unsafe.Pointer(&line[0])),
		flags, uintptr(unsafe.Pointer(&block[0])), uintptr(unsafe.Pointer(cwd)),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&created)))
	// Every argument above reaches the call as a plain number, which is not
	// a reference the collector can see: without this, nothing stops it
	// freeing any of them while Windows is still reading them.
	runtime.KeepAlive(user)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(cwd)
	runtime.KeepAlive(secret)
	runtime.KeepAlive(line)
	runtime.KeepAlive(block)
	if r == 0 {
		return -1, fmt.Errorf("starting %s as %s: %w", commandLine, username, callErr)
	}
	defer syscall.CloseHandle(created.Process)
	defer syscall.CloseHandle(created.Thread)

	if err := j.assign(created.Process); err != nil {
		procTerminateProcess.Call(uintptr(created.Process), 1)
		return -1, err
	}
	procResumeThread.Call(uintptr(created.Thread))

	return j.waitOrStop(created.Process)
}

// environmentBlock turns a list of "NAME=VALUE" strings into the
// double-NUL-terminated wide block CREATE_UNICODE_ENVIRONMENT expects: each
// entry NUL-terminated in turn, the whole block closed by one more NUL.
func environmentBlock(env []string) ([]uint16, error) {
	if len(env) == 0 {
		return []uint16{0, 0}, nil
	}
	var block []uint16
	for _, entry := range env {
		encoded, err := syscall.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("encoding the environment entry %q: %w", entry, err)
		}
		block = append(block, encoded...) // UTF16FromString already NUL-terminates entry
	}
	return append(block, 0), nil
}
