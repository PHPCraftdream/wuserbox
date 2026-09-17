# What a sandbox may touch

What a sandbox can write without being handed anything, what the delete
boundary is and why it is the property this tool exists to provide, and how
to keep your own settings out of reach of what runs inside. The short
version is in the [README](../README.md); this is the whole of it.

## What is writable by default

* the project directory;
* the sandbox's own thin profile, which `HOME`, `APPDATA`, `TEMP` and `TMP`
  point inside — everything in it but the registry hive, which the account
  the profile belongs to cannot write into. That last part is a known defect
  rather than a boundary drawn on purpose; [limits](limits.md) records it.

That is the whole list. Your real `~/.config`, `~/.claude` and the other
agent directories are **not** handed over: what an agent needs from them is
copied into the sandbox's own profile instead, and a grant an older wuserbox
left on the real ones is taken back the first time a sandbox is reconciled.

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

The restricted token is the other answer to the same problem, and for a while
the two were treated as alternatives. It checks every access a second time
against a short list of the sandbox's own identities. It closed the gap and
ran into a wall: MSYS2 programs — `bash` and everything built on it — could
not start under one at all. The measurement is in
[docs/investigations](docs/investigations/msys-under-a-restricted-token.md).

What the wall was made of turned out to be *whose* identities. An MSYS runtime
writes permissions naming the account it runs as and then reopens its own
objects — its own process token among them — and a token restricted to a list
that could not name that user was refused by them. A user's own identifier can
never be a restricting one. An account's can, and under an account of its own
the name in those permissions *is* the account. So the restriction went back
on, on top of the account, where it costs nothing and closes what the account
alone does not.

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
  restricted-token flag, which sandboxed code cannot clear, and the name of
  the account it is running as, which it cannot change either.
* Sensitive entries that do not exist yet are taken as empty placeholders under
  the same locked permissions before the profile root is handed over, so a
  sandbox cannot claim one of those names first. A name is taken as whatever it
  is meant to be: `.ssh` becomes a directory, not an empty file that would
  break every tool reading it. The one case that cannot be
  reserved is a shell startup file whose presence would hide another that is
  really there; wuserbox says so instead of creating it.
* Each project has its own group and its own temp directory, so one sandbox
  cannot write into another's project.

