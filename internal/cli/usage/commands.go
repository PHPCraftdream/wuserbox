package usage

// Commands is every command wuserbox accepts, in the order the overview lists
// them. The dispatcher is checked against this list, so a command cannot be
// added in one place and forgotten in the other.
var Commands = []Command{
	{
		Name:    "run",
		Summary: "run a command sandboxed for the current directory",
		Call:    "run [options] -- <command> [arguments...]",
		Detail: `Starts a command under a token that reads everything you can read and
writes only where this project's sandbox is allowed to: the project
directory, the directories you have handed over, and a temporary
directory of its own that TEMP and TMP point at.

The sandbox is created on first use, which needs administrator rights
once. Later runs need none. The command keeps your console, your
environment and your exit code, so it behaves like any other program
you start from the shell.

Everything after -- belongs to the command being run, including its own
flags, so "wuserbox run -- git --version" reaches git untouched.`,
		Options: []Option{
			{"--dir <d>", "project directory (default: the current one)"},
			{"--rw <d>", "hand over another directory for writing, repeatable"},
			{"--ro <d>", "hand over another directory for reading, repeatable"},
			{"--no-ai", "withhold the AI agent directories, and take back any already given"},
			{"--home-writes", "let the sandbox create files in the profile root"},
		},
		Examples: []string{
			`wuserbox run -- claude`,
			`wuserbox run -- npm test`,
			`wuserbox run --rw C:\build\out -- cargo build`,
			`wuserbox run --dir C:\projects\app -- git status`,
		},
	},
	{
		Name:       "init",
		Summary:    "create the group and apply permissions",
		Call:       "init [options]",
		Elevates:   true,
		Privileged: true,
		Detail: `Creates the local group that carries this project's identity, applies
the permissions the sandbox needs, and locks wuserbox's own settings so
the code it runs cannot change them.

You rarely need this: "run" does it the first time it is used in a
directory. Reach for it when you want the consent prompt out of the way
before starting an agent, or when you want to hand over directories
ahead of time.

Running it again is safe. It repairs missing permissions and leaves the
ones already in place alone.`,
		Options: []Option{
			{"--dir <d>", "project directory (default: the current one)"},
			{"--rw <d>", "hand over another directory for writing, repeatable"},
			{"--ro <d>", "hand over another directory for reading, repeatable"},
			{"--no-ai", "do not hand over the AI agent directories"},
			{"--home-writes", "let the sandbox create files in the profile root"},
		},
		Examples: []string{
			`wuserbox init`,
			`wuserbox init --no-ai`,
			`wuserbox init --dir C:\projects\app --rw C:\projects\shared`,
		},
	},
	{
		Name:       "grant",
		Summary:    "allow this sandbox to use one more directory",
		Call:       "grant <dir> [--ro] [--dir project]",
		Privileged: true,
		Detail: `Hands one more directory to the sandbox of a project. Without --ro the
sandbox may create, change and delete anything under it; with --ro it
may only read it.

The permission is recorded and stays in force for later runs, until
"revoke" takes it back or "rm" removes the sandbox. It is not written
to the rules file, so it does not follow the project to another machine;
use "add-dir" for that.

Administrator rights are asked for only if you do not own the target
directory.`,
		Options: []Option{
			{"--ro", "read access only, no writing"},
			{"--dir <d>", "project whose sandbox is meant (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox grant C:\build\out`,
			`wuserbox grant C:\reference\docs --ro`,
			`wuserbox grant /c/tools --dir C:\projects\app`,
		},
	},
	{
		Name:       "revoke",
		Summary:    "take an allowance back",
		Call:       "revoke <dir> [--dir project]",
		Privileged: true,
		Detail: `Removes the sandbox's permission on a directory and forgets it. The
directory itself is untouched; only the permission entry for the
project's group goes away.

A directory listed in the rules file comes back on the next run. Use
"remove-dir" to forget it there as well.`,
		Options: []Option{
			{"--dir <d>", "project whose sandbox is meant (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox revoke C:\build\out`,
			`wuserbox revoke ~/scratch --dir C:\projects\app`,
		},
	},
	{
		Name:       "add-dir",
		Summary:    "allow a directory and remember it in the rules",
		Call:       "add-dir <dir> [--ro] [--dir project]",
		Privileged: true,
		Detail: `Does what "grant" does, and writes the directory into the rules file at
%USERPROFILE%\.wuserbox.ktav so every later run of this project gets it
again, even after the sandbox is removed and rebuilt.

This is the command to ask for when a sandboxed program reports that a
write was refused and the directory is one it should have.`,
		Options: []Option{
			{"--ro", "read access only, no writing"},
			{"--dir <d>", "project the rule belongs to (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox add-dir C:\projects\pc\tools`,
			`wuserbox add-dir C:\projects\pc\logs`,
			`wuserbox add-dir C:\reference --ro`,
		},
	},
	{
		Name:       "remove-dir",
		Summary:    "forget a directory and take it back",
		Call:       "remove-dir <dir> [--dir project]",
		Privileged: true,
		Detail: `Deletes the directory from the rules file and, if the sandbox currently
holds it, revokes the permission too.`,
		Options: []Option{
			{"--dir <d>", "project the rule belongs to (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox remove-dir C:\projects\pc\logs`,
		},
	},
	{
		Name:    "name",
		Summary: "show the group name for a directory",
		Call:    "name [dir]",
		Detail: `Prints the group a directory maps to, and the directory the name was
derived from, separated by a tab.

The name is the folder plus a hash of the full path, so two projects
called "app" in different places never collide, and the same directory
always gives the same name.`,
		Examples: []string{
			`wuserbox name`,
			`wuserbox name C:\projects\app`,
		},
	},
	{
		Name:    "path",
		Summary: "show the directory behind a group",
		Call:    "path <group>",
		Detail: `Prints the project directory a sandbox group belongs to. The directory
is stored in the group's own comment, so this works without any file on
disk and survives a reinstall.`,
		Examples: []string{
			`wuserbox path wub-app-d6e9a21f`,
		},
	},
	{
		Name:    "list",
		Summary: "list the sandboxes on this machine",
		Call:    "list",
		Detail: `Prints every sandbox group and the directory it belongs to, one per
line. Useful for finding sandboxes left behind by a project that was
renamed or deleted; remove one with "rm --dir <directory>".`,
		Examples: []string{
			`wuserbox list`,
		},
	},
	{
		Name:       "rm",
		Summary:    "delete the sandbox of a project",
		Call:       "rm [--dir project]",
		Elevates:   true,
		Privileged: true,
		Detail: `Takes back every permission the sandbox was given, deletes its
temporary directory and its bookkeeping, and removes the group.

Your files stay where they are. The rules file keeps its entries, so
starting the project again rebuilds the same sandbox.`,
		Options: []Option{
			{"--dir <d>", "project to remove (default: the current directory)"},
		},
		Examples: []string{
			`wuserbox rm`,
			`wuserbox rm --dir C:\projects\old`,
		},
	},
	{
		Name:    "audit",
		Summary: "list directories writable by Everyone",
		Call:    "audit [depth]",
		Detail: `Walks the fixed drives and prints the directories that Everyone may
write to. Those stay writable inside a sandbox as well, because Everyone
has to be one of the restricting identifiers for programs to start at
all, so this is the list of places the boundary does not cover.

The depth is how many levels below each drive root to look; two by
default. A larger number takes longer.`,
		Examples: []string{
			`wuserbox audit`,
			`wuserbox audit 3`,
		},
	},
	{
		Name:    "version",
		Summary: "show the release this build came from",
		Call:    "version",
		Detail: `Prints the release, the architecture it was built for and the Go
version that built it. A build made from a checkout rather than a
release reports "dev".`,
		Examples: []string{
			`wuserbox version`,
		},
	},
}
