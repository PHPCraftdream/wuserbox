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
   the full path, so the mapping works in both directions with no database.
   Every permission wuserbox grants is an ordinary NTFS entry naming this
   group, and the group is what decides what the sandbox may touch.

2. **A local account per project**, the group's only member, such as
   `wub-d6e9a21f`. The command runs as *that account* — not as you. It cannot
   log on at the sign-in screen and cannot log on remotely.

   So an access succeeds only where the group, or one of the memberships the
   account needs in order to function at all, has a permission of its own.
   Reading stays open because the account also carries `Everyone` and
   `BUILTIN\Users`, which between them cover the system, and your own read
   group, which covers your own profile and which nothing but your own sandbox
   accounts ever join.

Nothing is emulated or intercepted. The kernel enforces it, child processes
inherit it, and a sweeping `rm -rf` stops at the same boundary as everything
else.

### What the sandbox gets instead of your profile

Because it is not you, it does not have your profile. It gets one of its own:
a directory wuserbox builds, holding an empty registry hive and three folders,
handed to the program as its `USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA`
and `TEMP`. It costs about two and a half megabytes.

The files and directories named in the `profile:` section of the rules file
are **copied in** from your profile before each run — that is where an
agent's credentials and settings come from — and the list is pre-filled with
the common agents' state directories when the rules file is created. Nothing
on the sensitive list — `~/.ssh`, `~/.netrc`, `~/.npmrc`, `~/.gitconfig` — is
in that default, and you can add what you need.

The real directories themselves are never handed over: a sandbox reaches
`~/.claude` only through the copy in its own profile, and a legacy grant left
by an older version of wuserbox is taken back the first time `--init` or an
ordinary run reconciles the sandbox, whichever comes first.

**Nothing is copied back.** A sandbox able to write into the files its own
credentials came from could rewrite them, which is the shape of hole this
exists to close. The cost is real — an agent that refreshes a token inside
the sandbox refreshes a copy, and the next run starts from your original
again. Where that means logging in every run, log in once outside the
sandbox so the refreshed file is in your own profile.

This is the part that changed most recently, and it changed because MSYS2
programs — `bash` and everything built on it — cannot start under a restricted
token at all. The whole measurement is in
[docs/investigations](docs/investigations/msys-under-a-restricted-token.md),
and what replaced it in
[docs/design](docs/design/an-account-of-its-own.md).

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

The sandbox runs as **an account of its own** instead. Deleting answers to
that account like every other access, rather than to yours — which closes the
same gap for a directory another sandbox holds, and for a protected file
inside a directory the sandbox may otherwise write to. Your own Full Control
over your own profile is simply not something the sandbox carries, because it
is not you.

This is the second answer to the same problem. The first was a fully
restricted token, which checked every access a second time against the
sandbox's own identifier. It closed the gap and worked, right up against a
wall: MSYS2 programs — `bash` and everything built on it — cannot start under
one at all. The measurement is in
[docs/investigations](docs/investigations/msys-under-a-restricted-token.md).

The account carries `Everyone` and `BUILTIN\Users`, or it could not read
System32, Program Files, or start a program that opens a window at all. That
makes any directory those two may write to a directory every sandbox may
write to, whichever one it was handed to. So
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
default, which is what the read groups are for: one per person, named
`wub-read-<hash>`, granted reading on that person's profile the first time
they build a sandbox from it, and joined only by their own sandbox accounts.

One group for the whole machine is what this used to be, and it was safe only
for as long as a sandbox was your own token cut down — the first of the two
access checks still had to pass as the person you really were, and nobody was
a member of a group with no members. An account joins a group for real, so on
a machine with two people that one group would have let one person's sandbox
read the other's profile, private keys included. `--init` splits it and takes
the old group's permission off your profile.

## Protecting your settings

Code running in the sandbox must not be able to widen its own permissions:

* `~/.wuserbox.ktav` and the per-sandbox bookkeeping get a fixed permission
  list with inheritance switched off. They cannot be changed or deleted from
  inside, even if a permission is later granted on the directory around them.
* The shell startup files and credential directories in the profile root get
  the same treatment: `.bashrc`, `.profile`, `.gitconfig`, `.npmrc`, `.netrc`,
  `.ssh`, `.gnupg`, `.aws` and their neighbours. That fixed list names the
  owner, the system, administrators and your own read group, and nobody else:
  your sandbox reads them through that group, which nothing but your own
  sandbox accounts join, while another person on the same machine — and their
  sandboxes — are no closer to your keys than before wuserbox was installed. Reading them is what
  this allows; changing or destroying them is what it refuses.
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

* **You have to be an administrator yourself.** Not to run a sandbox — that
  needs nothing — but to build one. A standard user's consent prompt asks for
  *another* administrator's credentials, and the elevated half then runs as
  that person: the group, the account and the profile are made on the machine,
  while the record naming them is written into that administrator's profile
  and sealed to their account, where yours can neither read nor open it.
  wuserbox detects this, refuses rather than looping, and tells you what is
  left on the machine and how to remove it. Making it work means the elevated
  half doing only what needs administrator rights and handing the rest back,
  which is not built.
* **Reading is not restricted.** The sandbox sees your keys, tokens and browser
  data. It prevents damage, not a determined leak.
* **What it cannot read is what belongs to your account rather than to a file.**
  Credential Manager, DPAPI secrets and mapped drives are yours, and the
  sandbox is not you. Anything sealed under your account stays sealed. This is
  a consequence of the account, not a feature built on top of it, so do not
  lean on it the way you would lean on the file boundary, which is tested.
* **The network is not restricted.**
* **Directories writable by `Everyone`, `BUILTIN\Users` or
  `Authenticated Users` stay writable**, and this is the one place where what a
  sandbox may change is wider than what it was handed. A sandbox carries all
  three — the first for programs to start at all, the second to read System32
  and Program Files, the third by virtue of being an account that logged on —
  so a sandbox may change whatever the machine already lets every local account
  change, without that directory ever having been granted. Many machines ship
  `C:\ProgramData` that way. `wuserbox --audit` lists what it finds under any
  of them. So the guarantee to hold wuserbox to is **a sandbox cannot change
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
* **A protected file inside a granted tree stays protected**, and that is
  deliberate rather than an oversight. Handing a directory over reaches
  everything under it that still listens to it, but an object whose
  permissions are its own and do not inherit — `~/.ssh`, `~/.aws`, `~/.netrc`
  and the rules file, which wuserbox protects itself — does not. Granting a
  home directory therefore does not hand over the keys in it. The cost is that
  anything else protected in there is out of the sandbox's reach too; grant it
  by name if the sandbox should have it.
* **Two commands changing overlapping trees wait for each other.** Handing a
  directory over sweeps everything under it, so `wuserbox --grant C:\work` and
  `wuserbox --grant C:\work\inner` are two changes to the same objects under
  two different names. Each change claims its own tree outright and every
  directory above it in passing, so the inner one waits for the outer one to
  finish rather than crossing it. Two directories where neither holds the other
  run at the same time as before: they share only the directories above them
  both, and those are claimed in a way that does not exclude. The order is
  fixed, from the volume root downwards, so neither can end up holding what the
  other waits for.
* **Revoking does not reach a file that is already open.** Windows checks
  permissions when a file is opened and not again afterwards, so a sandbox that
  already had something open keeps writing through that handle until it closes
  it. `wuserbox --revoke` and `wuserbox --rm` succeed against open files and
  refuse every new attempt straight away, but they are not a way to stop a
  program that is already running. Stop it first.
* **`HKEY_CURRENT_USER` is the sandbox's own, and starts empty.** A program
  that saves settings in the registry can, and they go into the sandbox's hive
  rather than yours — so they are there next run, and nothing of yours is read
  from there. What starts blank is anything that expected your own settings:
  locale and the like.
* **Files the sandbox creates are owned by the sandbox's account**, not by you.
  You keep being able to delete them, because the project directory carries an
  entry for you, but a listing will show an owner you do not recognize.
* **Interface isolation is weak.** A sandboxed process shares your desktop and
  clipboard.
* **A batch file's arguments still expand variables.** Starting a `.cmd` or
  `.bat` goes through the command interpreter, which replaces `%NAME%` before
  the script runs. Punctuation is quoted, so an argument cannot start a second
  command, but there is no escape for expansion on a command line.
* **Renaming the project directory** changes the group, leaving the old sandbox
  behind. `wuserbox --list` shows it, `wuserbox --rm --dir <old>` removes it.
* **A file whose other name is outside stops a grant.** A hard link is not a
  second file, it is a second name for the same one, and a permission list
  belongs to the file rather than to the name. Handing a directory over
  therefore hands over every name the files in it have, wherever those names
  are — measured, with the sandbox's own entry turning up on a file outside the
  tree. So a grant looks the other names up first and refuses where one of them
  lies outside what is being handed over. Links that stay inside the tree are
  left alone, and that distinction is not a nicety: package managers deduplicate
  within one directory, and in a real profile that is thousands of files under
  `~/.config` and `~/.claude`, none of them reaching outside. `--allow-links`
  hands the tree over regardless, for the case where you know what the outside
  name is. The sandbox cannot make such a link itself against anything it may
  not already write, so this is a grant reaching further than it says rather
  than a way out that a sandbox takes.
* **A record that cannot be read is not a sandbox that never was.** What a
  sandbox holds is written in one file per sandbox, and the entries it names
  sit on directories all over the disk with nothing else pointing at them. A
  copy of that file from before the last save is kept beside it, so a record
  that stops parsing still has something behind it naming those directories,
  and `wuserbox --rm` says what happened and finishes with the copy instead of
  refusing to run. Every other command stops there on purpose: acting on a
  sandbox whose permissions are unknown is how permissions get left behind.
  If both the record and the copy are gone, only the project directory can
  still be cleared — the group's own comment remembers that much — and removal
  says so rather than reporting a success that means less than it looks.
* **Handing over a directory reads all of it.** Every object under it is looked
  at before anything is changed, and the ones that answer to nobody above are
  written, so the cost grows with the number of objects in the tree and not
  with its depth. On an ordinary project it is not noticeable. What it costs on
  a tree of hundreds of thousands of files has not been measured, only reasoned
  about, so that is said here rather than turned into a number nobody took.

## Layout

```
cmd/wuserbox      the executable
internal/win      Windows calls: identifiers, permissions, tokens, processes, groups
internal/policy   what a sandbox is allowed: grants, presets, rules, bookkeeping
internal/sandbox  identity, creation, execution
internal/cli      the commands
internal/base     what has no opinion about sandboxes: exit codes, locks, paths
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

One test reads the user's profile directory, which needs that user's own read
group, created the first time they build a sandbox. Creating a group needs
administrator rights, so that test skips rather than fails without them. The full lifecycle test creates an
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
