# Limits worth knowing

Everything a sandbox does not stop, said plainly. A boundary described only
by what it holds is a boundary somebody will lean on where it does not.


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
* **Reading is not restricted, once a directory is where the sandbox can
  reach it.** The sandbox sees your keys, tokens and browser data because
  your profile is granted to a read group made for exactly that, the moment
  `--init` builds the sandbox. A directory somewhere else whose permissions
  name you and nobody else is not covered by that group, and reading it
  needs the same `--grant` a write would — `--ro` if reading is all that is
  wanted. Once a directory is reachable, this prevents damage, not a
  determined leak.
* **What it cannot read is what belongs to your account rather than to a file.**
  Credential Manager, DPAPI secrets and mapped drives are yours, and the
  sandbox is not you. Anything sealed under your account stays sealed. This is
  a consequence of the account, not a feature built on top of it, so do not
  lean on it the way you would lean on the file boundary, which is tested.
* **The network is not restricted.**
* **Directories writable by `Everyone` or `BUILTIN\Users` stay writable**, and
  this is the one place where what a sandbox may change is wider than what it
  was handed. A sandbox carries both — the first for programs to start at all,
  the second to read System32 and Program Files — so a sandbox may change
  whatever the machine already lets every local account change, without that
  directory ever having been granted. Many machines ship
  `C:\ProgramData` that way. `wuserbox --audit` lists what it finds under
  either. So the guarantee to hold wuserbox to is **a sandbox cannot change
  what the machine does not already let every local account change, anywhere
  it was not handed** — somebody's own files, another sandbox's files, and
  anything named to its owner alone are outside a sandbox's reach; a shared
  drop box that was never granted is not.

  Inside a granted tree this does not apply: handing a directory over reaches
  everything under it, so a subdirectory somebody left open to `Everyone` or
  `Users` is narrowed along with the rest.

  **What it is worth, in practice.** Measured on an ordinary desk: 44 such
  directories, all but three of them under `C:\ProgramData`. The root itself
  is stock Windows — every account may create entries there, by design, and
  that is not a machine in poor shape. The rest are vendor directories an
  installer left open to `Users`, which is an industry habit rather than
  anything wuserbox did or can undo.

  As damage this is small. None of it is your files, another sandbox's files,
  or anything named to an owner. An agent that runs something reckless in a
  sandbox does it to the project or to a home directory, and both are covered.
  The worst case here is a sandbox spoiling some application's shared state,
  which a reinstall puts back.

  As a way *out* of the sandbox it is worth a look, and not because of
  wuserbox: several of those vendor directories belong to products whose
  services run as `SYSTEM`. Where such a service reads a configuration file or
  loads a library from a directory any account may write to, anything running
  as any account on that machine can aim at it — sandboxed or not. wuserbox
  neither creates that nor closes it.

  Which is the shape of the whole limitation: **wuserbox never makes this
  worse.** Without it an agent runs as you, and may change those 44 directories
  *and* everything of yours. With it, only those 44. The exposure is strictly
  smaller; it is not zero.

  Narrowing them is a one-time job with `icacls`, it helps every program on
  the machine rather than only sandboxes, and it is deliberately not something
  wuserbox does for you: rewriting permissions on shared system directories
  reaches other people's software and other accounts on the machine, and some
  applications genuinely need an ordinary user to write there. Taking that
  decision away from whoever owns the machine is not this tool's to make, so
  `--audit` shows and does not touch.

  Only those two. A directory writable by some other identity — `Authenticated
  Users`, which several machines grant on a second drive, or `INTERACTIVE`,
  which Windows itself puts on the shared public profile — is out of a
  sandbox's reach, because the second access check names a short list and
  neither is on it. That is what the restriction buys over the account alone,
  and it buys it without anybody having to keep a list of such identities
  complete: an ordinary interactive token carries at least nine. `--audit`
  does not list them either.

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
* **`HKEY_CURRENT_USER` is the sandbox's own, starts empty — and cannot be
  written where it matters, which is a known defect, not a design choice.**
  The hive is seeded per sandbox, so nothing of yours is read from there, and
  what starts blank is anything that expected your own settings: locale and
  the like. Reading it works. Writing under `HKCU\Software`, where Windows
  programs keep their settings, does not: the account the hive was seeded for
  is refused with "Access is denied" — measured, on both slots of
  [the probe that found it](investigations/a-hive-per-slot.md), and again by
  PowerShell on the key it writes at startup. Settings a program tries to
  save are not there next run because they never landed. The one place that
  accepts a write is `HKCU\Software\Classes`, and that hive is the profile
  service's work, not wuserbox's. Why the account is refused its own hive is
  an open question; the investigation carries the measurement that asks it
  and a hypothesis, and this document gets rewritten when there is an answer.
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

