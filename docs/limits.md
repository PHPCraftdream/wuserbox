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
  "reads what its own account and your read group can reach" is the promise
  this tool opens with. Closing the shared-writable hole that way makes a
  different, narrower tool, so it is not a change to make quietly on top of
  this one.
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
* **Every lock wuserbox takes is yours alone, and excludes nobody else's.**
  The slot a run leases, the locks the commands wait on and the tree locks
  above all live in the state directory under your own profile, beside the
  records they guard. That is what keeps them out of a sandbox's reach, and
  it is also why two people using wuserbox on one machine hold two sets that
  never meet. A second operator's sandboxes, grants and records are theirs
  regardless, and none of it touches yours; what the two of you can still
  share is a directory on the disk, because a directory belongs to nobody.
  There the locks keep nothing apart: handing the same directory over from
  two accounts at the same moment reads the same permission list twice,
  alters two copies and writes both back, and one of the two grants lands on
  its record but not on the disk, or the other way round. That is the exact
  race the tree locks exist to stop within one person's commands; across two
  accounts nothing stops it. What it costs is a directory drifted out of
  step with the records, and nothing notices by itself: granting or
  revoking the same tree again writes the list and the record back in step.

  This one is reasoned rather than measured, and the machine it takes is
  narrow: two people, both running wuserbox commands against the same
  directory in the same instant. The fix that would close it is a lock set
  the whole machine shares, kept where both accounts can reach it -- which
  means a lock either account can pre-create, deny or hold, a harder problem
  than the one it would answer. Until there is a reason to build that, the
  answer is not to run two operators' commands into the same directory at
  once.
* **Revoking does not reach a file that is already open.** Windows checks
  permissions when a file is opened and not again afterwards, so a sandbox that
  already had something open keeps writing through that handle until it closes
  it. `wuserbox --revoke` and `wuserbox --rm` succeed against open files and
  refuse every new attempt straight away, but they are not a way to stop a
  program that is already running. Stop it first.
* **`HKEY_CURRENT_USER` is the sandbox's own, starts empty, and is the
  sandbox's to write.** The hive is seeded per sandbox, so nothing of yours
  is read from there, and what starts blank is anything that expected your
  own settings: locale and the like. Settings a program saves under
  `HKCU\Software` — where Windows programs keep theirs — land in the hive
  and are there next run. `HKCU\Software\Classes` is a second hive the
  Windows profile service builds and permissions for the account rather
  than wuserbox, and it behaves the same as the rest.

  Corrected 2026-09-17, the day the defect was fixed. Until then this entry
  read the opposite: the permission list wuserbox put on the hive's root
  granted the account **on the root and nothing below it**, so keys the
  first logon creates — `Software` among them — were permissioned by
  whoever made them, and the account was refused there, reading as much as
  writing. The three grants now reach the subkeys, written the way the
  profile service writes its own. [The
  investigation](investigations/a-hive-per-slot.md) carries the measurement,
  the refusal transcript and the two permission lists side by side.
  Sandboxes initialized before the fix keep the old lists until they are
  removed and built again.
* **A `cleanup:` glob is yours to aim, and the guard over it is a net rather
  than a proof.** The globs in the rules file delete from the sandbox's
  profile, and wuserbox refuses the run if one of them could reach the
  registry hive or the transaction files Windows keeps beside it — deleting
  those does not clear a cache, it destroys the sandbox's
  `HKEY_CURRENT_USER`. That refusal works by asking whether the glob's
  language meets the shape of those names, and the shape carries a GUID and
  a counter that are different on every machine, so the question is answered
  by analysis rather than by looking at what is on disk. Analysis of that
  kind has been wrong here before, in a way nothing noticed until somebody
  wrote the glob that slipped through. Write globs that name what the
  sandbox wrote — a directory, an extension you recognize — rather than
  broad ones trimmed with wildcards until they look right, and read what
  `--dry-run` says a cleanup would take before you let it run.
* **Files the sandbox creates are owned by the sandbox's account**, not by you.
  You keep being able to delete them, because the project directory carries an
  entry for you, but a listing will show an owner you do not recognize.

  **Ownership used to be a way out of every narrowing, and is not any more.**
  Windows hands whoever owns an object the right to rewrite its permission
  list, whatever that list says and even where it refuses exactly that —
  measured on an ordinary desk, on a file whose entries denied its own owner
  the right to change them, which the owner then changed anyway. So `--ro` and
  `--revoke` did not hold against anything the sandbox had created: it could
  hand itself back whatever it liked. wuserbox now writes an `OWNER RIGHTS`
  entry on objects the sandbox's account owns, which replaces what ownership
  implies with reading and no more, and which the owner cannot take off again.
  Objects **you** own are not touched, so nothing of yours changes.

  What it does not reach is a file the sandbox creates *between* two sweeps.
  Until the next `--grant`, `--ro` or `--revoke` passes over it, that file
  holds its owner's right to be re-permissioned and the sandbox can widen it.
  The contents are the sandbox's own; what it costs is a path inside your tree
  standing open wider than you would expect. Narrowing again closes it.

  **Two entries in such a list will look wrong and are not.** `icacls` on a
  file the sandbox created inside a handed-over tree prints an `OWNER RIGHTS:`
  line carrying no rights at all, above the real one — the residue of
  replacing whatever an owner-rights entry said before, where there was
  nothing to replace. And it prints `NULL SID`, an identifier that matches no
  account there has ever been: it grants nobody anything and is there as a
  mark, saying that this list was written by a sweep and mirrors what the tree
  above handed down at that moment rather than a decision anybody made about
  this file. Without the mark a later narrowing cannot tell a list wuserbox
  wrote from one somebody sealed on purpose, and it would either leave the
  first stale or overwrite the second.
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
* **Profile refresh refuses an external hard-link destination.** The profile
  is scanned when a sandbox starts, but a writable profile can change after
  that scan. Before a refresh truncates an existing copied file, it enumerates
  all names for the file object and refuses if any name is outside the
  profile. Links whose names all remain inside the profile are allowed.
  The check is point-in-time at each
  handover and at profile initialization; it is not a filesystem watcher.
  Any later operation that writes a profile or reapplies a grant must check
  the destination again. `--allow-links` applies only to an explicit
  directory handover and is not inherited by profile maintenance. UAC is
  required to create or repair a sandbox, but it is not a permanent hard-link
  guarantee for a process that already has write access to a directory and
  access to a target file.
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
