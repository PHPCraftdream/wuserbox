package usage

import "strings"

// Text is what "wuserbox help" prints. It is written for whoever reads it
// first after a write was refused, which is usually a coding agent rather than
// a person, so it says what the boundary is and what to ask the user for.
//
// The command list is built from Commands, so the overview and the detailed
// entries cannot drift apart.
var Text = intro + commandList() + options + paths

const intro = `wuserbox - run a command that reads everything you can read, but writes
only where you allow.

WHAT THIS MEANS FOR A PROGRAM RUNNING INSIDE

  You can read everything the user can read: the whole disk, the toolchain,
  the user's settings and credentials.

  You can write only to:
    * the project directory you were started in, and everything under it
    * any directory the user has granted for this project
    * your own temporary directory, which TEMP and TMP point at

  Anywhere else a write fails with "Access is denied". That is Windows
  enforcing a permission boundary, not a broken tool and not a bug to work
  around. Retrying, changing permissions or asking for administrator rights
  will not help: the commands that widen access refuse to run from inside a
  sandbox, and so does elevation.

  WUSERBOX_DIR holds the project directory and WUSERBOX_GROUP the name of the
  sandbox, so you can tell you are inside one.

NEEDING ANOTHER DIRECTORY

  Ask the user to run one of these in a terminal that is NOT inside the
  sandbox, then start you again:

    wuserbox add-dir C:\path\to\dir        allow writing there, now and from now on
    wuserbox add-dir C:\path\to\dir --ro   allow reading it, nothing more
    wuserbox grant C:\path\to\dir          allow writing there for this project

  add-dir also records the directory in %USERPROFILE%\.wuserbox.ktav, so it
  survives; grant does the same without writing it down. Say which directory
  you need and why, and let the user decide.

COMMANDS

`

const options = `
  Run "wuserbox help <command>" for the full entry on any of them.

OPTIONS SHARED BY run AND init

  --dir <d>       project directory (default: the current directory)
  --rw <d>        allow writing to another directory, repeatable
  --ro <d>        allow reading another directory, repeatable
  --no-ai         do not hand over the AI agent directories
  --home-writes   let the sandbox create files in the profile root

  --rw and --ro stay in force for later runs as well, until "wuserbox revoke"
  takes them back or "wuserbox rm" removes the sandbox.

OPTIONS SHARED MORE WIDELY

  --dry-run          show what would change, change nothing, start nothing
  --json             print the result as JSON, on the commands that offer it
  --quiet            no progress messages, errors only
  --non-interactive  fail instead of asking for administrator rights, so a
                     script never stops at a dialog nobody can click

EXIT CODES

  0  what was asked was done
  1  something went wrong
  2  the command line was wrong
  3  the answer is no: a refused access check, or a sandbox asking for more
  4  administrator rights are needed and prompts are switched off
  5  the rules file does not parse or contradicts itself
  6  what was named does not exist

  One exception: "run" returns whatever the command inside returned, so the
  code you read after it is the sandboxed program's own.

  With --json a failure is reported as JSON too, on the error stream:
  {"error": "...", "code": 3, "status": "denied"}. A script reading the
  output therefore meets one shape whether the command worked or not.
`

const paths = `
PATHS

  Any usual spelling works, and the order of options does not matter:

    C:\tools    c:/tools    /c/tools    /mnt/c/tools    /cygdrive/c/tools
    ~/tools     %USERPROFILE%\tools     $HOME/tools     ..\tools
`

// commandList renders the one-line summaries, aligned on the call.
func commandList() string {
	width := 0
	for _, command := range Commands {
		if len(command.Call) > width {
			width = len(command.Call)
		}
	}
	var b strings.Builder
	for _, command := range Commands {
		b.WriteString("  wuserbox " + command.Call +
			strings.Repeat(" ", width-len(command.Call)+2) + command.Summary + "\n")
	}
	return b.String()
}
