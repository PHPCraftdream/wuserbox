package usage

import "strings"

// Text is what "wuserbox --help" prints. It is written for whoever reads it
// first after a write was refused, which is usually a coding agent rather than
// a person, so it says what the boundary is and what to ask the user for.
//
// The command list is built from Commands, so the overview and the detailed
// entries cannot drift apart.
var Text = intro + commandList() + options + paths

const intro = `wuserbox - run a command that reads what you can read, and changes nothing
the machine does not already let every local account change, anywhere you
did not allow it to.

USAGE

  wuserbox [options] <program> [arguments...]   run a program sandboxed
  wuserbox <command> [options]                  everything else

  Running is the default: the first word is a program unless it is one of
  the commands below. "wuserbox notepad.exe" is a whole command line. Options
  belong to wuserbox and come before the program; everything from the program
  onwards belongs to the program.

  Commands carry a dash, and that is what tells them from a program:
  "wuserbox --list" asks wuserbox, "wuserbox list" starts a program called
  list. Nothing without a dash is a command, so a program is never shadowed
  by one, help included: "wuserbox help" tries to run a program called help,
  and "wuserbox --help" or "-h" is what asks.

WHAT THIS MEANS FOR A PROGRAM RUNNING INSIDE

  You are not the user. You run as a local account of this sandbox's own,
  which is what decides everything below.

  You can read what the user can read: the whole disk, the toolchain, the
  user's settings and credential files. What you cannot reach is what belongs
  to the user's account rather than to a file: Credential Manager, anything
  sealed with DPAPI, mapped drives. Nor a directory whose permissions name
  the user alone and nothing else -- reading the user's profile works because
  it is granted to a group made for that, and a locked-down directory
  somewhere else has to be granted to this sandbox like any other.

  Your profile is not the user's. USERPROFILE, HOME, APPDATA, LOCALAPPDATA
  and TEMP all point inside a profile built for this sandbox, and
  HKEY_CURRENT_USER is its own and starts empty. Settings you save are kept
  there and are still there next run. What was copied in from the user's
  profile is whatever the rules file names; nothing is ever copied back.

  You can write only to:
    * the project directory you were started in, and everything under it
    * any directory the user has granted for this project
    * your own profile, which TEMP and TMP point inside

  Deleting is bounded the same way, by the same thing: what a permission
  names is this sandbox's group, the account's only way to anything is being
  a member of it, and DELETE is checked against that like every other access.
  A sweep like "rmdir /s" or "rm -rf" started in the wrong place empties what
  the sandbox was given and stops at its edge.

  Anywhere else a write fails with "Access is denied", with one exception the
  tool does not hide: a directory the machine already lets every local
  account write to stays writable, because this sandbox has to carry Everyone
  and BUILTIN\Users to start a program and read the system at all.
  C:\ProgramData holds such directories on many machines, and
  "wuserbox --audit" lists the ones on this one. Writing there is not a way
  in to anything of the user's, and it is still not a place to put work.

  A refusal is Windows enforcing a permission boundary, not a broken tool and
  not a bug to work around. Retrying, changing permissions or asking for
  administrator rights will not help: the commands that widen access
  refuse to run from inside a sandbox, and so does elevation.

  WUSERBOX_DIR holds the project directory and WUSERBOX_GROUP the name of the
  sandbox, so you can tell you are inside one.

NEEDING ANOTHER DIRECTORY

  Ask the user to run one of these in a terminal that is NOT inside the
  sandbox, then start you again:

    wuserbox --add-dir C:\path\to\dir        allow writing there, now and from now on
    wuserbox --add-dir C:\path\to\dir --ro   allow reading it, nothing more
    wuserbox --grant C:\path\to\dir          allow writing there for this project

  add-dir also records the directory in %USERPROFILE%\.wuserbox.ktav, so it
  survives; grant does the same without writing it down. Say which directory
  you need and why, and let the user decide.

COMMANDS

`

const options = `
  Run "wuserbox --help <command>" for the full entry on any of them, or
  "wuserbox --help --all" for every entry at once, followed by the format of
  the rules file and the environment wuserbox sets and reads. That is the
  whole manual, and it needs nothing else to hand.

RUNNING AND CONFIGURING ARE SEPARATE

  Starting a program takes the sandbox as it stands and changes nothing, so
  a run has no options that decide what may be written. Those belong to:

    wuserbox --add-dir <dir> [--ro]   allow a directory, now and from now on
    wuserbox --grant <dir> [--ro]     allow it for this project, unrecorded
    wuserbox --init --no-ai           build the sandbox without agent directories
    wuserbox --init --home-writes     let it create files in the profile root

  A directory allowed this way stays in force for later runs, until
  "wuserbox --revoke" takes it back or "wuserbox --rm" removes the sandbox.

  Each of those asks for administrator rights, and that is the point: what a
  sandbox may write to and delete in is settled by someone who can answer a
  consent prompt, not by the program running inside it. Starting a program
  never asks.

  What a sandbox may write is therefore decided in one place and readable
  afterwards with "wuserbox --explain", instead of depending on which command
  line happened to start the program.

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

  One exception: a run returns whatever the program inside returned, so the
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
