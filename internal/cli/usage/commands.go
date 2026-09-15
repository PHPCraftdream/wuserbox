package usage

// Commands is every command wuserbox accepts, in the order the overview lists
// them. The dispatcher is checked against this list, so a command cannot be
// added in one place and forgotten in the other.
var Commands = []Command{
	{
		Name:    "run",
		Default: true,
		Summary: "run a program sandboxed for the current directory",
		Call:    "[options] <program> [arguments...]",
		Detail: `Starts a program under a token that reads everything you can read and
writes only where this project's sandbox is allowed to: the project
directory, the directories you have handed over, and a temporary
directory of its own that TEMP and TMP point at.

This is what wuserbox does when the first word is not one of its
commands, so "wuserbox notepad.exe" is a whole command line. Options
belong to wuserbox and come before the program; everything from the
program onwards belongs to the program, its own flags included, so
"wuserbox git --version" reaches git untouched.

A program is never shadowed by a wuserbox command that happens to share
its name: "wuserbox list" runs a program called list, and "wuserbox
--list" asks wuserbox for the command, because nothing without a dash is
a command. "wuserbox --run -- <program>" still works too, spelling this
command out and marking where its arguments end, and means exactly what
leaving out "--run --" means.

The sandbox is created on first use, which needs administrator rights
once. Later runs need none. The program keeps your console, your
environment and your exit code, so it behaves like any other program
you start from the shell.

A run changes nothing about the sandbox. What may be written is decided
by "--init", "--grant" and "--add-dir", and is the same whichever
command line starts the program.`,
		Options: []Option{
			{"--dir <d>", "project directory (default: the current one)"},
			{"--dry-run", "show what the sandbox holds and start nothing"},
			{"--json", "print the plan as JSON instead of lines"},
			{"--quiet", "no progress messages, errors only"},
			{"--non-interactive", "fail instead of asking for administrator rights"},
		},
		Exits: "Whatever the program inside returned, so the code you read is its own.",
		Examples: []string{
			`wuserbox claude`,
			`wuserbox npm test`,
			`wuserbox notepad.exe`,
			`wuserbox --dir /c/projects/app git status`,
			`wuserbox --run -- list`,
		},
	},
	{
		Name:       "init",
		Summary:    "create the group and apply permissions",
		Call:       "--init [options]",
		Elevates:   true,
		Privileged: true,
		Detail: `Creates the local group that carries this project's identity, applies
the permissions the sandbox needs, and locks wuserbox's own settings so
the code it runs cannot change them.

You rarely need this: a run does it the first time one happens in a
directory. Reach for it when you want the consent prompt out of the way
before starting an agent, or when you want to hand over directories
ahead of time — a run has no options for that, deliberately.

Running it again is safe, and is the way to repair a sandbox: every
permission is applied afresh rather than taken on trust from the
record, so an entry removed by hand comes back.`,
		Options: []Option{
			{"--dir <d>", "project directory (default: the current one)"},
			{"--rw <d>", "hand over another directory for writing, repeatable"},
			{"--ro <d>", "hand over another directory for reading, repeatable"},
			{"--no-ai", "do not hand over the AI agent directories"},
			{"--home-writes", "let the sandbox create files in the profile root"},
			{"--dry-run", "show what would be handed over, hand over nothing"},
			{"--json", "print the plan as JSON instead of lines"},
			{"--quiet", "no progress messages, errors only"},
			{"--non-interactive", "fail instead of asking for administrator rights"},
		},
		Examples: []string{
			`wuserbox --init`,
			`wuserbox --init --no-ai`,
			`wuserbox --init --dir C:\projects\app --rw C:\projects\shared`,
		},
	},
	{
		Name:       "grant",
		Summary:    "allow this sandbox to use one more directory",
		Call:       "--grant <dir> [--ro] [--dir project]",
		Privileged: true,
		Detail: `Hands one more directory to the sandbox of a project. Without --ro the
sandbox may create, change and delete anything under it; with --ro it
may only read it.

The permission is recorded and stays in force for later runs, until
"--revoke" takes it back or "--rm" removes the sandbox. It is not
written to the rules file, so it does not follow the project to another
machine; use "--add-dir" for that.

Administrator rights are asked for only if you do not own the target
directory.

Handing a directory over rewrites the permissions of everything in it,
not only of the directory itself, so that no sandbox reaches it through
a permission left lying about: anything letting "Everyone" or
"BUILTIN\Users" change something is narrowed, above and below. That is
why the first grant on a large tree takes a while. Reading is left as
it was, and nothing is opened up that was not open before.

What you ask for here outranks the agent preset. Narrowing one of the
directories the preset hands over, say "--grant ~/.claude --ro", stays
narrow: later runs apply the preset again and leave your decision alone.`,
		Options: []Option{
			{"--ro", "read access only, no writing"},
			{"--dry-run", "show what would change, change nothing"},
			{"--json", "print the result as JSON instead of lines"},
			{"--non-interactive", "fail instead of asking for administrator rights"},
			{"--dir <d>", "project whose sandbox is meant (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox --grant C:\build\out`,
			`wuserbox --grant C:\reference\docs --ro`,
			`wuserbox --grant /c/tools --dir C:\projects\app`,
		},
	},
	{
		Name:       "revoke",
		Summary:    "take an allowance back",
		Call:       "--revoke <dir> [--dir project]",
		Privileged: true,
		Detail: `Removes the sandbox's permission on a directory and forgets it. The
directory itself is untouched; only the permission entry for the
project's group goes away.

It reaches inside as well. A directory handed to another sandbox keeps
a permission list of its own, which may hold a copy of what this
sandbox had at the time, and rewriting the directory above it would
not reach that copy. Anything still naming this sandbox underneath is
taken away too, except a directory inside that this same sandbox was
granted in its own right.

A directory listed in the rules file comes back on the next run. Use
"--remove-dir" to forget it there as well.`,
		Options: []Option{
			{"--dry-run", "show what would change, change nothing"},
			{"--json", "print the result as JSON instead of lines"},
			{"--non-interactive", "fail instead of asking for administrator rights"},
			{"--dir <d>", "project whose sandbox is meant (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox --revoke C:\build\out`,
			`wuserbox --revoke ~/scratch --dir C:\projects\app`,
		},
	},
	{
		Name:       "add-dir",
		Summary:    "allow a directory and remember it in the rules",
		Call:       "--add-dir <dir> [--ro] [--dir project]",
		Privileged: true,
		Detail: `Does what "--grant" does, and writes the directory into the rules file at
%USERPROFILE%\.wuserbox.ktav so every later run of this project gets it
again, even after the sandbox is removed and rebuilt.

This is the command to ask for when a sandboxed program reports that a
write was refused and the directory is one it should have.`,
		Options: []Option{
			{"--ro", "read access only, no writing"},
			{"--dry-run", "show what would change, change nothing"},
			{"--json", "print the result as JSON instead of lines"},
			{"--non-interactive", "fail instead of asking for administrator rights"},
			{"--dir <d>", "project the rule belongs to (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox --add-dir C:\projects\pc\tools`,
			`wuserbox --add-dir C:\projects\pc\logs`,
			`wuserbox --add-dir C:\reference --ro`,
		},
	},
	{
		Name:       "remove-dir",
		Summary:    "forget a directory and take it back",
		Call:       "--remove-dir <dir> [--dir project]",
		Privileged: true,
		Detail: `Deletes the directory from the rules file and, if the sandbox currently
holds it, revokes the permission too.`,
		Options: []Option{
			{"--dry-run", "show what would change, change nothing"},
			{"--json", "print the result as JSON instead of lines"},
			{"--non-interactive", "fail instead of asking for administrator rights"},
			{"--dir <d>", "project the rule belongs to (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox --remove-dir C:\projects\pc\logs`,
		},
	},
	{
		Name:    "name",
		Summary: "show the group name for a directory",
		Call:    "--name [dir]",
		Detail: `Prints the group a directory maps to, and the directory the name was
derived from, separated by a tab.

The name is the folder plus a hash of the full path, so two projects
called "app" in different places never collide, and the same directory
always gives the same name.`,
		Examples: []string{
			`wuserbox --name`,
			`wuserbox --name C:\projects\app`,
		},
	},
	{
		Name:    "path",
		Summary: "show the directory behind a group",
		Call:    "--path <group>",
		Detail: `Prints the project directory a sandbox group belongs to. The directory
is stored in the group's own comment, so this works without any file on
disk and survives a reinstall.`,
		Examples: []string{
			`wuserbox --path wub-app-d6e9a21f`,
		},
	},
	{
		Name:    "list",
		Summary: "list the sandboxes on this machine",
		Call:    "--list [--json]",
		Detail: `Prints every sandbox group and the directory it belongs to, one per
line. Useful for finding sandboxes left behind by a project that was
renamed or deleted; remove one with "--rm --dir <directory>".`,
		Options: []Option{
			{"--json", "print the list as JSON instead of lines"},
		},
		Examples: []string{
			`wuserbox --list`,
			`wuserbox --list --json`,
		},
	},
	{
		Name:       "rm",
		Summary:    "delete the sandbox of a project",
		Call:       "--rm [--dir project]",
		Elevates:   true,
		Privileged: true,
		Detail: `Takes back every permission the sandbox was given, deletes its
temporary directory and its bookkeeping, and removes the group.

Your files stay where they are. The rules file keeps its entries, so
starting the project again rebuilds the same sandbox.

If something will not go, usually a temporary directory another program
still has open, the command says so and fails with exit code 1. The
bookkeeping and the group are left alone in that case, because they are
what a second run needs to finish the removal.

If the bookkeeping itself cannot be read, this is the one command that
carries on anyway, because leaving permissions behind is what it is here
to prevent. It says so, works from the copy kept behind the record, and
clears the project directory as well. Anything handed over elsewhere
after that copy was made cannot be found by anything, and the command
says that too rather than reporting a clean removal.`,
		Options: []Option{
			{"--dry-run", "show what would change, change nothing"},
			{"--json", "print the result as JSON instead of lines"},
			{"--non-interactive", "fail instead of asking for administrator rights"},
			{"--dir <d>", "project to remove (default: the current directory)"},
		},
		Exits: "1 when something would not go and the sandbox is left for a second attempt.",
		Examples: []string{
			`wuserbox --rm`,
			`wuserbox --rm --dir C:\projects\old`,
		},
	},
	{
		Name:    "audit",
		Summary: "list directories writable by Everyone or BUILTIN\\Users",
		Call:    "--audit [depth]",
		Detail: `Walks the fixed drives and prints the directories that Everyone or
BUILTIN\Users may write to, saying which of the two it found. Those stay
writable inside a sandbox as well, because both have to be restricting
identifiers for a program to start at all and to read the system it runs
on, so this is the list of places the boundary does not cover.

Nothing else is listed. A directory writable by some other group — by
"Authenticated Users", say, which several machines grant on a second
drive — is not reachable from inside a sandbox, because a sandbox's
restricted list does not carry it.

The depth is how many levels below each drive root to look; two by
default. A larger number takes longer.`,
		Examples: []string{
			`wuserbox --audit`,
			`wuserbox --audit 3`,
		},
	},
	{
		Name:    "explain",
		Summary: "show what this sandbox may touch, and why",
		Call:    "--explain [--dir project] [--json]",
		Detail: `Prints the sandbox of a project: its group, its temporary directory,
every path it holds, the access it has on each, and where that came
from. The source is the useful part: a directory the rules file asks
for every time reads differently from one that was handed over once by
hand.

Each permission is then checked against Windows rather than trusted, in
both directions. Less access than recorded means a permission was lost.
More access than recorded matters even more: a directory written down
as readable that the sandbox can write to is the situation this tool
exists to prevent. Either way "wuserbox --init" puts the permissions
back as they were meant to be.`,
		Options: []Option{
			{"--dir <d>", "project to explain (default: the current directory)"},
			{"--json", "print the report as JSON instead of lines"},
		},
		Examples: []string{
			`wuserbox --explain`,
			`wuserbox --explain --json`,
			`wuserbox --explain --dir C:\projects\app`,
		},
	},
	{
		Name:    "check",
		Summary: "ask whether one thing would be allowed",
		Call:    "--check <path> [--operation read|write|create|delete] [--dir project] [--json]",
		Detail: `Asks Windows whether the sandbox could do something to a path, using
the same restricted token a run would get. Nothing is opened for
writing and nothing is created, so asking costs nothing and leaves no
trace.

This is the honest way to find out before trying. For a path that does
not exist, "create" asks about the directory that would hold it.

The answer is in the exit code as well as the text, so a script can act
on it without reading the output.`,
		Options: []Option{
			{"--operation <op>", "read, write, create or delete (default: write)"},
			{"--dir <d>", "project whose sandbox is meant (default: the current directory)"},
			{"--json", "print the answer as JSON instead of lines"},
		},
		Exits: "0 allowed, 3 refused, 1 the question could not be asked.",
		Examples: []string{
			`wuserbox --check C:\build\out --operation create`,
			`wuserbox --check .\notes.md --operation write`,
			`wuserbox --check C:\Windows\System32 --operation write --json`,
		},
	},
	{
		Name:    "config",
		Summary: "read the rules file",
		Call:    "--config show|path|validate [--dir project] [--json]",
		Detail: `Reads %USERPROFILE%\.wuserbox.ktav without opening an editor.

  show      print the rules, or only the rule for one project
  path      print where the file is
  validate  check it without applying it

The check looks for what a hand-edited file collects: a directory
listed twice, a directory listed as both writable and readable, which
quietly costs write access, a project written out more than once, where
only the first rule is ever applied, and directories that no longer
exist. The
last is reported apart from the rest, because a directory going away is
not a mistake in the file. A real problem ends with exit code 5.

With --dir the whole file is still read and only the answer is narrowed,
so a project written out twice is still reported against that project.
A project with no rule at all ends with exit code 6, in both show and
validate, rather than passing for having nothing to check.`,
		Options: []Option{
			{"--dir <d>", "show or check one project's rule only"},
			{"--json", "print the result as JSON instead of lines"},
		},
		Exits: "5 when the file does not parse or contradicts itself, 6 when a named project has no rule.",
		Examples: []string{
			`wuserbox --config show`,
			`wuserbox --config path`,
			`wuserbox --config validate --json`,
			`wuserbox --config validate --dir .`,
		},
	},
	{
		Name:    "version",
		Summary: "show the release this build came from",
		Call:    "--version",
		Detail: `Prints the release, the architecture it was built for and the Go
version that built it. A build made from a checkout rather than a
release reports "dev".`,
		Examples: []string{
			`wuserbox --version`,
		},
	},
}
