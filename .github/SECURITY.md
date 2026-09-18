# Security policy

wuserbox exists to make one promise, so a report that the promise is broken is
the most useful thing anybody can send.

## The promise

A sandboxed process runs under its own local account, not yours. **It reads
what that account and the read group it belongs to can reach — not everything
you can read** — and **writes and deletes only inside what it was granted**,
plus its own temporary directory and whatever the machine already lets every
local account write to. It must not reach another sandbox's directories.

## What counts as a vulnerability

Anything that lets a process running under `wuserbox` change or remove
something outside what that sandbox was handed, or reach what another sandbox
was handed. That includes:

- writing, deleting, renaming or changing the permissions of a file or
  directory outside the granted set;
- one sandbox reaching another sandbox's granted directories or temporary
  directory;
- a grant that reaches further than the directory it names;
- making wuserbox itself apply a permission nobody asked for, or leave one in
  force that the record does not mention.

## What does not

These are the tool's design, stated in the README under "Limits worth
knowing", and a report of one is not a vulnerability:

- **Reading is not restricted within what the sandbox can reach.** The
  sandbox sees your keys, tokens and browser data. wuserbox prevents damage,
  not a determined leak.
- **Directories the machine itself makes writable to everybody** — parts of
  `C:\Windows\Temp`, public folders, some of `C:\ProgramData` — stay writable.
  wuserbox never narrows what it did not hand over.
- **A file already open** keeps its handle. Windows checks permissions when a
  file is opened and not afterwards, so revoking a grant does not stop a
  process that is already running.
- **Interface isolation is weak.** A sandboxed process shares your desktop and
  clipboard.
- Anything that needs administrator rights to set up in the first place.

If you are not sure which side of the line something falls on, report it. A
report that turns out to be a documented limit costs a short reply; the other
mistake costs more.

## Reporting

Use GitHub's private vulnerability reporting on this repository: **Security →
Report a vulnerability**. It opens a private thread with the maintainers, so
nothing is public until there is something to say.

Please include the Windows version, the wuserbox version (`wuserbox
--version`), the exact commands that set up the sandbox, and the command that
crossed the boundary. A failing test is worth more than a description: every
boundary property in this repository is pinned by one, and a report that
arrives as a test is a report that cannot be misread.

Expect an acknowledgement within a week. There is no bounty.

## Supported versions

The latest release. wuserbox is young enough that fixes go into the next
version rather than into patches of older ones.
