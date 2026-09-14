# wuserbox

[![tests](https://github.com/PHPCraftdream/wuserbox/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/wuserbox/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/PHPCraftdream/wuserbox?sort=semver)](https://github.com/PHPCraftdream/wuserbox/releases)
[![go](https://img.shields.io/github/go-mod/go-version/PHPCraftdream/wuserbox)](https://go.dev)
[![platform](https://img.shields.io/badge/platform-windows-0078d4)](https://github.com/PHPCraftdream/wuserbox)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

Run a command on Windows so that it **reads everything you can read**, but
**writes only where you allow**. Intended for AI coding agents: they need your
whole toolchain and configuration, and they must not be able to damage anything
outside the project.

```
wuserbox claude
```

Running is what wuserbox does unless the first word is one of its commands, so
that line is complete. Options belong to wuserbox and come before the program;
everything from the program onwards belongs to the program.

## Installing

With [Scoop](https://scoop.sh), which also keeps it up to date:

```
scoop bucket add wuserbox https://github.com/PHPCraftdream/scoop-bucket
scoop install wuserbox
```

With npm, handy when the agents themselves are installed that way:

```
npm install -g wuserbox
```

From source, if you have Go:

```
go install github.com/PHPCraftdream/wuserbox/cmd/wuserbox@latest
```

Or take the archive from [Releases](https://github.com/PHPCraftdream/wuserbox/releases)
and put `wuserbox.exe` on your PATH. Keep the `ktav_cabi-windows-*.dll` beside
it: that is the configuration parser, and with it in place the first run needs
no network.

## How it works

Two Windows mechanisms, nothing else:

1. **A local group per project.** The folder name plus a hash of its full path
   become a group such as `wub-wuserbox-d6e9a21f`. The group's comment stores
   the full path, so the mapping works in both directions with no database. The
   group has no members and cannot log on.

2. **A fully restricted token.** The command runs under *your* account, with
   your environment, your `HKEY_CURRENT_USER` and your credentials, but the
   token carries a list of restricting identifiers. Every access is checked
   twice: against you *and* against that list. Not only writes — `DELETE` and
   `FILE_DELETE_CHILD` go through the same check, which is what a
   write-restricted token could not do and why this one replaced it.

   So an access succeeds only where one of those identifiers has a permission
   of its own, which wuserbox grants as ordinary NTFS entries. Reading stays
   open because the list also carries `Everyone` and `BUILTIN\Users`, which
   between them cover the system, and `wub-read`, a group with no members, for
   your own profile.

Nothing is emulated or intercepted. The kernel enforces it, child processes
inherit it, and a sweeping `rm -rf` stops at the same boundary as everything
else.

## Commands

| Command | Effect |
| --- | --- |
| `wuserbox [options] <program> [args...]` | run a program sandboxed for the current directory |
| `wuserbox --init` | create the group and apply permissions |
| `wuserbox --grant <dir> [--ro]` | allow one more directory |
| `wuserbox --revoke <dir>` | take an allowance back |
| `wuserbox --add-dir <dir> [--ro]` | remember a directory in the rules and grant it |
| `wuserbox --remove-dir <dir>` | forget a directory and revoke it |
| `wuserbox --name [dir]` | show the group for a directory |
| `wuserbox --path <group>` | show the directory behind a group |
| `wuserbox --list` | list sandboxes |
| `wuserbox --rm` | delete group, permissions and temp directory |
| `wuserbox --explain` | what this sandbox may touch, and why |
| `wuserbox --check <path> --operation write` | ask whether one thing would be allowed |
| `wuserbox --config show\|path\|validate` | read and check the rules file |
| `wuserbox --audit [depth]` | list directories writable by Everyone or `BUILTIN\Users` |
| `wuserbox --version` | show the release this build came from |
| `wuserbox --help [command]` | the overview, or the full entry for one command |
| `wuserbox --help --all` | the whole manual: every entry, the rules file and the environment |

A command carries a dash, and that is what tells it from a program:
`wuserbox --list` asks wuserbox, `wuserbox list` starts a program called list.
Nothing without a dash is a command, so a program is never shadowed by one —
help included: `wuserbox help` tries to run a program called help, and
`wuserbox --help` or `-h` is what asks.

Every command carries its own entry: `wuserbox --help grant` prints what it
does, which options it reads, what it returns in its exit code, whether it asks
for administrator rights and a few examples. `wuserbox --grant --help` prints
the same thing. The overview is written for a coding agent that has just been
refused a write: it says where the boundary is and which command to ask the
user for.

`wuserbox --help --all` prints all of it at once — every entry in full,
followed by the format of the rules file and the environment wuserbox sets and
reads. Nothing in it is written twice: the manual, the overview and the single
entries are all rendered from one list, and a test holds each command's
documented options to the flags it really registers, so the manual cannot fall
behind the program.

Running and configuring are separate. Starting a program takes the sandbox as
it stands and changes nothing, so a run has no options that decide what may be
written: `--dir <d>` picks the project and that is all. What a sandbox may
write is decided by `--init`, `--grant` and `--add-dir` — `--rw <d>`, `--ro
<d>`, `--no-ai` and `--home-writes` belong to `--init`, and to the rules file
the other two write. The answer is therefore in one place, readable
afterwards with `wuserbox --explain`, rather than depending on which command
line happened to start the program.

`--dry-run` shows what a command would change without changing it, taking both
the rules file and the permissions the sandbox holds into account, `--json`
gives the diagnostic commands machine-readable output — a failure under
`--json` is reported as JSON too, so a script meets one shape either way —
`--quiet` drops the progress messages, and `--non-interactive` fails instead
of raising a consent prompt, so a script never stops at a dialog nobody can
click.

A directory handed over with `--grant`, `--add-dir` or `--init --rw` stays
available on later runs too, until `wuserbox --revoke` takes it back. Nothing
is given up when the process ends: a permission that vanished whenever a run
was interrupted would be a promise the tool could not keep.

What you ask for outranks the agent preset. Narrowing one of the directories
the preset hands over, say `wuserbox --grant ~/.claude --ro`, stays narrow:
later runs apply the preset again and leave that decision alone.

Directory names are taken as written when they name something that exists, so
a project called `build$STAGE` is that project and not `build`.

Directories may be written in any usual form, and the option order does not
matter:

```
C:\tools    c:/tools    /c/tools    /mnt/c/tools    /cygdrive/c/tools
~/tools     %USERPROFILE%\tools     $HOME/tools     ..\tools
```

Deciding what a sandbox may write to needs administrator rights, so `--init`,
`--rm`, `--grant`, `--revoke`, `--add-dir` and `--remove-dir` raise a consent
prompt. Starting a program does not, unless the sandbox does not exist yet, in
which case it is built first.

## What is writable by default

* the project directory;
* a private temp directory, which `TEMP` and `TMP` point at;
* the whole of `~/.config`, where many tools keep their settings;
* the state directories of AI agents found on the machine: `~/.claude`,
  `~/.codex`, `~/.crush`, `~/.rush`, `~/.gemini`, `~/.grok`, `~/.qwen`,
  `~/.factory`, `~/.continue`, opencode, Goose and others, plus
  `~/.claude.json` as a single file.

The profile root itself is **read-only**. Handing it over would make every
dotfile already in it writable, because Windows pushes an inherited permission
down to the files that are already there. Agents that rewrite a dotfile in the
profile root through a temporary file and a rename need `wuserbox --init
--home-writes`; with that flag every sensitive file there is refused one by
one.

## The delete boundary

Refusing writes is not enough on its own. `DELETE` and `FILE_DELETE_CHILD`
fall outside the mapping a write-restricted token checks a second time, so a
sandbox held to its own directories by permissions alone still carried the
user's own right to delete wherever their account already held it — and by
default a Windows profile grants its owner Full Control over everything in
it, which includes removing what is inside a directory whatever the thing
inside says about itself. Writing to a file elsewhere was refused; deleting
it was not.

The sandbox runs on a **fully restricted token** instead: every access, not
only writes, is checked a second time against the sandbox's own identifier,
`DELETE` and `FILE_DELETE_CHILD` included. Deleting now answers to that
identifier like everything else, rather than to the caller's own account —
which closes the same gap for a directory another sandbox holds, and for a
protected file inside a directory the sandbox may otherwise write to.

`Everyone` and `BUILTIN\Users` have to sit in that same restricted list, or
the sandbox could not read System32, Program Files, or start a program that
opens a window at all. That makes any directory those two may write to a
directory every sandbox may write to, whichever one it was handed to. So
handing a directory over rewrites its whole permission list:

* whatever `Everyone` and `Users` held there is narrowed to reading — never
  refused outright, because Windows honors a matching refusal over a matching
  permission for one token whatever order the list is in, and every sandbox's
  restricted list carries both identifiers, so a refusal aimed at either would
  refuse the sandbox its own directory too;
* an entry a directory **above** handed down is rewritten too, by making the
  list the directory's own. Rewriting the directory alone would not have
  touched it — a handed-down entry is a copy belonging to the parent — and
  Windows adds up every entry that matches, so the writable copy would have
  won back the part the narrowed one gave up;
* everything **below** is walked as well. Handing an entry down replaces only
  the handed-down part of what is underneath, so a subdirectory with a
  writable entry of its own keeps it, and every sandbox keeps reaching it.
  This is what makes a grant take as long as it does on a large tree;
* the right to rewrite a permission list counts as a changing right, and so
  does taking ownership. Either one is enough on its own: a sandbox left
  holding it hands itself the rest;
* nothing is *added* for those two, and nothing is replaced: the changing
  rights are taken out of what an entry already covers, and an entry left
  with nothing goes. A directory they could not read stays one they cannot
  read, because handing them reading in the name of narrowing is a widening
  with better manners;
* whatever was taken from them is handed back to the person doing the granting
  by name, so a grant never costs somebody the directory they were granting.

Taking a directory back reaches as far as handing it over did. Pinning a
granted directory's list copies into it whatever it was being handed at the
time — including another sandbox's entry, where the directory sits inside one
that sandbox holds. A copy answers to nobody: rewriting the directory above it
no longer reaches it. So revoking a directory, or narrowing it to read-only,
also takes that sandbox's own entries off everything underneath, except where
the record says it was granted something inside in its own right.

Reading is untouched by any of this: a sandbox still reads everything its
user can read that `Everyone`, `BUILTIN\Users`, or its own account already
covers. The profile is the one place none of those reaches by Windows' own
default, which is what `wub-read` is for — a machine-wide group nobody is a
member of, granted reading on a profile the first time somebody builds a
sandbox from it. No ordinary token carries it, so it lets a sandbox past its
second check without letting another account on the machine read anything.

## Protecting your settings

Code running in the sandbox must not be able to widen its own permissions:

* `~/.wuserbox.ktav` and the per-sandbox bookkeeping get a fixed permission
  list with inheritance switched off. They cannot be changed or deleted from
  inside, even if a permission is later granted on the directory around them.
* The shell startup files and credential directories in the profile root get
  the same treatment: `.bashrc`, `.profile`, `.gitconfig`, `.npmrc`, `.netrc`,
  `.ssh`, `.gnupg`, `.aws` and their neighbours. That fixed list names the
  owner, the system, administrators and `wub-read`, and nobody else: a sandbox
  reads them through the group it carries among its restricting identifiers,
  while another account on the same machine is no closer to your keys than it
  was before wuserbox was installed.
* `--init`, `--rm`, `--grant`, `--revoke`, `--add-dir` and `--remove-dir`
  refuse to run from inside a sandbox, and wuserbox never asks for
  administrator rights from there. The check reads the kernel's
  restricted-token flag, which sandboxed code cannot clear.
* Sensitive entries that do not exist yet are taken as empty placeholders under
  the same locked permissions before the profile root is handed over, so a
  sandbox cannot claim one of those names first. A name is taken as whatever it
  is meant to be: `.ssh` becomes a directory, not an empty file that would
  break every tool reading it. The one case that cannot be
  reserved is a shell startup file whose presence would hide another that is
  really there; wuserbox says so instead of creating it.
* Each project has its own group and its own temp directory, so one sandbox
  cannot write into another's project.

## Standing rules

`~/.wuserbox.ktav` records the directories a project always gets:

```
projects: [
    {
        dir: C:/Users/name/projects/app
        rw: [
            C:/Users/name/projects/tools
            C:/Users/name/projects/logs
        ]
    }
]
```

Edit it with `wuserbox --add-dir <dir>` and `wuserbox --remove-dir <dir>`, or
by hand. Paths are stored with forward slashes, because ktav reads a backslash as
an escape, but every spelling above is accepted when the file is read, in the
`dir` key as well as in the lists.

## Environment

Set for the program running inside a sandbox:

| Variable | Holds |
| --- | --- |
| `WUSERBOX_DIR` | the project directory the sandbox belongs to |
| `WUSERBOX_GROUP` | the name of the sandbox, which is also its group |
| `TEMP`, `TMP` | the sandbox's own temporary directory, which `--rm` deletes |

Read by wuserbox itself:

| Variable | Effect |
| --- | --- |
| `WUSERBOX_CONFIG` | the rules file to read, instead of the one in the profile root |
| `WUSERBOX_NON_INTERACTIVE` | set by `--non-interactive`, and passed on, so a command that re-runs itself with more rights never stops at a dialog |

A program can tell it is inside a sandbox by `WUSERBOX_DIR` being set. What it
may write is not in the environment and cannot be changed from there;
`wuserbox --explain` is how to read it, from outside.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | what was asked was done |
| 1 | something went wrong |
| 2 | the command line was wrong |
| 3 | the answer is no: a refused access check, or a sandbox asking for more |
| 4 | administrator rights are needed and prompts are switched off |
| 5 | the rules file does not parse or contradicts itself |
| 6 | what was named does not exist |

A run is the exception: it returns whatever the program inside
returned, so the code you read after it is the sandboxed program's own.

## Limits worth knowing

* **Reading is not restricted.** The sandbox sees your keys, tokens and browser
  data, and can decrypt whatever your account can. It prevents damage, not a
  determined leak.
* **The network is not restricted.**
* **Directories writable by `Everyone` or `BUILTIN\Users` stay writable**, and
  this is the one place where what a sandbox may change is wider than what it
  was handed. Both have to be restricting identifiers — the first for programs
  to start at all, the second to read System32 and Program Files — so a
  sandbox may change whatever the machine already lets every local account
  change, without that directory ever having been granted. Many machines ship
  `C:\ProgramData` that way. `wuserbox --audit` lists what it finds under
  either. So the guarantee to hold wuserbox to is **a sandbox cannot change
  what the machine does not already let every local account change, anywhere
  it was not handed** — somebody's own files, another sandbox's files, and
  anything named to its owner alone are outside a sandbox's reach; a shared
  drop box that was never granted is not.

  Inside a granted tree this does not apply: handing a directory over reaches
  everything under it, so a subdirectory somebody left open to `Everyone` or
  `Users` is narrowed along with the rest.

  Only those two. A directory writable by some other group — `Authenticated
  Users`, which several machines grant on a second drive — is out of a
  sandbox's reach anyway, because a sandbox's restricted list does not carry
  it, so `--audit` does not list it either.

  **An AppContainer would close this, and would cost the other half of the
  tool.** An AppContainer token ignores `Everyone` and `BUILTIN\Users`
  entirely: it reaches a file only through the package's own identifier or
  through `ALL APPLICATION PACKAGES`. Windows puts that on `C:\Windows\System32`
  and `C:\Program Files`, measured on this machine, so the system and the
  toolchain would still be readable. It is not on a Windows profile and not on
  an ordinary data directory — also measured — so reading would stop being
  free: every directory the sandbox reads would have to be granted first, and
  "reads everything you can read" is the promise this tool opens with. Closing
  the shared-writable hole that way makes a different, narrower tool, so it is
  not a change to make quietly on top of this one.
* **`HKEY_CURRENT_USER` is read-only.** Command-line tools rarely care;
  anything that saves settings in the registry will fail to.
* **Interface isolation is weak.** A sandboxed process shares your desktop and
  clipboard.
* **A batch file's arguments still expand variables.** Starting a `.cmd` or
  `.bat` goes through the command interpreter, which replaces `%NAME%` before
  the script runs. Punctuation is quoted, so an argument cannot start a second
  command, but there is no escape for expansion on a command line.
* **The agent directories are shared.** Every sandbox may write `~/.config`,
  `~/.claude` and their neighbours, so a poisoned hook or setting there would
  run with full rights the next time you start a tool outside wuserbox. Use
  `--no-ai` if that matters, or narrow one of them: `wuserbox --grant
  ~/.config --ro` outranks the preset and stays.
* **Renaming the project directory** changes the group, leaving the old sandbox
  behind. `wuserbox --list` shows it, `wuserbox --rm --dir <old>` removes it.

## Layout

```
cmd/wuserbox      the executable
internal/win      Windows calls: identifiers, permissions, tokens, processes, groups
internal/policy   what a sandbox is allowed: grants, presets, rules, bookkeeping
internal/sandbox  identity, creation, execution
internal/cli      the commands
internal/exit     the exit codes every failure maps to
internal/e2e      escape attempts against a real sandbox
.github           tests and release workflows, build recipe, npm wrapper
```

## Tests and linting

```
go test ./...
go vet ./...
golangci-lint run --config .github/golangci.yml ./...
```

The linter configuration lives under `.github/` rather than the repository
root, so it has to be named on the command line. It turns on errcheck, govet,
staticcheck, ineffassign, unused, misspell, unconvert, nilerr and errorlint,
and excuses only the Windows calls whose second return value carries nothing:
releasing a handle or a buffer cannot usefully fail.

The end-to-end tests create real permissions under a synthetic identifier and
try to escape: writing outside the project, through a child process, into the
profile, into the registry, and deleting a whole tree. Most need no elevation.

One test reads the user's profile directory, which needs `wub-read` — the
group a fully restricted token needs to reach it, created once the first time
any sandbox is built. Creating a group needs administrator rights, so that
test skips rather than fails without them. The full lifecycle test creates an
actual local group and needs elevation for the same reason. Run both from an
elevated shell:

```
go test ./... -count=1
go test ./internal/e2e -run TestCLIFullLifecycle -v
```

## Releasing

A tag starting with `v` triggers the release workflow: it fetches the parser
library, builds both architectures with [GoReleaser](https://goreleaser.com),
publishes the archives and checksums, pushes the Scoop manifest to the bucket
repository and publishes the npm package.

```
git tag v0.1.0 && git push origin v0.1.0
```

Two secrets are needed: `BUCKET_TOKEN`, a token that may push to the Scoop
bucket repository, and `NPM_TOKEN`.

## License

Dual licensed: use it under the Apache License, Version 2.0, or the MIT
license, whichever suits you. Both texts are in [LICENSE](LICENSE).

    SPDX-License-Identifier: MIT OR Apache-2.0

Contributions come in under the same two licenses.
