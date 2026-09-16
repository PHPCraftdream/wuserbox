# Filling a sandbox's profile

**Status:** built, cleanup and validation included. The `profile:` section
used to name flat paths and copy each one whole; it now carries depth, masks
and exclusions, the shipped default uses them, and a run skips what has not
changed — a comparison of the source's size and modification time
(`internal/policy/profile/print.go`), accepted knowing it can miss an edit
that lands on the same size and is then given the original modification time
back. `cleanup:` is built in `internal/policy/profile/cleanup.go`: its globs
are cleared from the sandbox's own profile before a copy runs, through the
same `os.Root` everything else in this package writes through. The validation
and preview of the new shapes is built in `internal/cli/diagnose/profile.go`,
which answers what a hand-edited `profile:` or `cleanup:` section gets wrong
before a run does.

Follows [a sandbox with an account of its own](an-account-of-its-own.md),
which established what a sandbox's profile is and why it is ours rather than
Windows'. This is about what goes into it.

## What is wrong with naming whole paths

A `profile:` entry is a path relative to the user's profile root, and the
copier mirrors it: a file is copied, a directory is copied whole, and whatever
the destination holds under that name and the source does not is deleted.
There is no way to say anything else, and three things follow from that.

**A useful directory cannot be named.** `~/.codex` holds `auth.json` and
`config.toml`, which is what an agent needs to start logged in and configured,
and it holds a session history that was measured at 7.2 GB on one ordinary
machine — of which two SQLite databases of conversation history were 1.9 GB.
Naming the directory carries all of it into every sandbox on every run. So the
shipped default names files instead: `.codex/auth.json`, `.codex/config.toml`,
and twenty-two more like them. That list is 254 KB and it works, but it is a
list of every file every agent this project knows about keeps its credentials
in, maintained by hand, and it goes stale the moment an agent adds a file.

**The copy is all-or-nothing in the other direction too.** The default that
named the directories came to 72,320 files and 19,436 MB per sandbox per run.
That is why there is a 64 MB ceiling, and why a migration retires the old
default from rules files that still carry it.

**What the sandbox writes there does not survive.** `removeStrayChildren`
mirrors the source exactly, so anything under a copied directory that the
source does not have is deleted. For a credentials file that is right. For
`~/.codex/sessions` it is the opposite of right: those are the sandbox's own
sessions, written by the agent running inside, and a rule that copies the
directory wipes them on the next run. This is the case the format has to
answer, and answering it is what makes naming a directory safe at all.

## What was measured about ktav first

The format below puts objects in a list that holds strings today. Whether
ktav can carry that was the open question the whole design rested on, so it
was measured before anything was designed. Four probes, all passing:

1. **A list of mixed shapes round-trips.** `ktav.LoadsInto` is
   `json.Unmarshal` over flattened JSON, and `ktav.Dumps` falls through to
   `json.Marshal` for any type it does not handle natively. A type with
   `MarshalJSON`/`UnmarshalJSON` therefore decides its own shape in both
   directions, and a bare string and an object can sit in the same list.
2. **A hand-written mixed list loads.** Somebody editing the file by hand can
   put an object between two bare strings and ktav reads it.
3. **An old copied-list record parses as a ktav array.** The record of what a
   run put in a sandbox's profile is one path per line, which is already a
   valid top-level ktav array — ktav renders a top-level array as bare
   item-per-line with no brackets. One reader covers both the old records and
   the richer ones, with no format flag and no migration.
4. **Awkward paths survive bare item-per-line rendering.** A path with a
   space, square brackets, a `#` or a `:` in it round-trips unchanged. This
   was the most likely thing to break the record format and it does not.

One thing it cannot do, also measured: **`Dumps` writes an object's keys in
alphabetical order.** It flattens through `map[string]any` on the way out, and
Go maps are unordered, so `depth` comes before `path` whatever order the struct
declares. This is cosmetic and it is accepted rather than worked around —
rendering the section by hand to control key order would mean not using the
emitter for part of the file, which is a worse trade for a file wuserbox
writes once and a person edits afterwards in whatever order they like.

## The format

A `profile:` entry is either a path, exactly as today, or an object that says
more about one.

```
profile: [
    .claude.json
    .codex/auth.json
    {
        path: .codex
        depth: 2
        include: [
            *.json
            *.toml
        ]
        exclude: [
            sessions/**
            history/**
            *.db
        ]
    }
]
```

**A bare string means what it means today** and keeps meaning it: that path,
copied whole, a file as a file and a directory as a directory with everything
under it. Nothing about an existing rules file changes, nothing needs
migrating, and somebody who never wants the richer shape never meets it.

**An object is the same entry with limits on it.** Written back as a bare
string whenever no limit is set, so the file does not grow objects that say
nothing.

### `path`

Where the entry lives, relative to the user's profile root, with forward
slashes. Absolute paths, paths that climb out of the profile, and paths that
land on the profile root itself — `.`, or `foo/..`, or anything else
`filepath.Clean` turns into `.` — are all refused. That check exists
(`within`) and stays, and it runs in the copier itself rather than only at
validation: an entry of `.` makes the source the user's whole profile and
the destination the sandbox's whole profile, and `Copy` would mirror one
onto the other — copying everything the user owns into the sandbox, and
deleting from the sandbox everything the user's profile does not have, the
sandbox's own registry hive among it. Required.

### Repeating a path

A path may appear more than once in `profile:` only when every repetition
says exactly the same thing — the same `depth`, and the same `include` and
`exclude` masks. That case is harmless: the second copy lands on the first
and changes nothing, and validation reports it as the waste it is, not as
breakage.

A path repeated with different limits is refused outright, by the copier as
well as by validation, rather than given an order in which one entry wins.
`{ path: .codex, exclude: [sessions/**] }` followed by the bare `.codex`
reads as two ways of saying the same thing and is not: the second entry
copies `.codex` whole, and the mirroring behind it deletes what the first
entry's exclusion was protecting, because the mirror sees no exclusion the
second time around and the excluded path is not in the source. That is real
data loss arriving from a rules file that only looks redundant, and refusing
it is preferred over defining which entry wins — a rules file that quietly
means something other than what it reads like is worse than one that is
refused.

### `depth`

How far below `path` to descend, counting directories.

- omitted — no limit, which is what a bare string means
- `0` — the files directly in `path`, no subdirectories at all
- `1` — those, plus the files in each immediate subdirectory
- `n` — n levels of subdirectories

On the entry it does two jobs, and the second is the one that decides ties:
it bounds the entry when the entry names no masks at all, and it is the
**default** for every mask that does not name a depth of its own. A mask that
names one overrides it, including upwards — an entry at `depth: 0` with a mask
at `depth: 3` searches three levels for that mask. Any other reading would
make a per-mask depth unable to say the thing it exists to say, which is "the
credentials at the top, and this one other thing wherever it is filed".

`depth` on an entry naming a file is a contradiction and is refused at
validation rather than ignored.

### `include`

Masks a file must match to be copied. Omitted means everything is included;
present means a file is copied only if it matches at least one mask. A list,
always — one mask cannot name two extensions, and `auth.json` and
`config.toml` sitting side by side is the ordinary case rather than the
unusual one.

**A mask may carry a depth of its own**, which is how far below `path` that
mask is searched:

```
{
    path: .codex
    include: [
        *.json
        *.toml
        { mask: *.md, depth: 3 }
    ]
    exclude: [
        sessions/**
    ]
}
```

A bare mask uses the entry's depth; a mask that names one uses that instead.
This is the difference between "the credentials at the top of the directory"
and "the prompts, wherever they are filed" in one entry, and without it a
person needing both has to write the same path twice.

A mask carrying no depth is written back as a bare string, exactly like a bare
entry, so a list that says nothing extra stays a list of plain patterns.

### `exclude`

Masks that stop a copy — and this is the part that does more than filter.

**An excluded path is not copied, and what is already there is left alone.**
That is the whole reason directories become nameable. `~/.codex` with
`exclude: [sessions/**]` copies the credentials and the settings, does not
copy the session history, and — unlike everything the copier does today —
does not delete the sessions the agent inside the sandbox wrote there.
Without that second half the first half is useless: the copy would skip the
sessions and the mirroring would then delete them for not being in the source,
which is a slower way of doing the same damage.

So an exclusion is two statements at once: *do not bring this in* and *this is
the sandbox's to keep*. Both are needed and neither makes sense alone.

`exclude` wins over `include`. A path matching both is excluded, because the
narrower statement is the one somebody wrote on purpose.

An exclude mask may carry a depth like an include one, and the shapes are the
same on purpose — one rule to learn rather than two. It is rarely what anybody
wants: an exclusion bounded to the top two levels still lets the thing being
excluded through at the third, which is usually the opposite of the point. It
is allowed because refusing it would be a special case, and omitting the depth
is the answer almost every time.

### `cleanup`

A separate top-level section, not part of an entry:

```
cleanup: [
    .codex/sessions/**
    .claude/projects/**
    **/*.log
]
```

Globs cleared from the sandbox's own profile before a copy runs. Relative to
the profile root, matched the same way as the masks above.

Separate from `profile:` because it answers a different question. `profile:`
says what to bring in; `cleanup:` says what should not be sitting there when a
run starts, and the two lists overlap only by coincidence — a cache worth
clearing is usually one nothing copies. Putting cleanup inside an entry would
also mean a directory can only be cleaned by something that copies it, which
is exactly backwards: the things most worth clearing are the ones the sandbox
wrote itself.

Everything it deletes goes through the destination's `os.Root`, like every
other write in that package, so a junction the sandbox planted cannot lead it
out of the profile.

**What it may never match, refused at validation rather than skipped at run
time:** `NTUSER.DAT` and its companion files, because that is the sandbox's
registry and deleting it is deleting `HKEY_CURRENT_USER`; `UsrClass.dat` and
its own companion files, the per-user class registration hive the profile
service builds beside the registry once the account first logs on, at
`AppData\Local\Microsoft\Windows`; the profile root itself; and anything that
resolves outside the profile. A person who writes `cleanup: [**]` gets told
what is wrong with it, not a sandbox that fails to start next run for reasons
pointing nowhere near the rules file.

## What a mask is

`*`, `?`, `**`, and nothing else. No regular expressions — a rules file is
read by people who are looking for a path, and a regular expression in it
would be a second language to learn for a case that does not come up.

- `?` — one character, never a separator
- `*` — any run of characters within one segment, never a separator
- `**` — any number of whole segments, including none
- matching is case-insensitive, because Windows is

`**` is why `path.Match` from the standard library is not enough, and why this
is written here rather than taken from a dependency. It is a small matcher and
a mask language with no `**` cannot express "everything under sessions", which
is the case the format exists for.

### What a mask is matched against

Two cases, decided by whether the mask has a `/` in it:

- **No separator — the file's own name**, wherever it sits inside the depth
  that mask is allowed. `*.json` with `depth: 2` finds `auth.json` and
  `a/b/auth.json` and stops there. This is the case people write, and it is
  what "how many directories deep this mask searches" means.
- **A separator — the path relative to the entry's `path`**, anchored at it.
  `prompts/*.md` matches only what is directly in `prompts`. `sessions/**`
  matches everything filed under `sessions`, and `sessions` itself.

The second half of that last one is not a detail. An exclusion has to stop the
copier descending into the directory at all, not merely skip the files it
finds there, or excluding a large tree would still cost the walk.

Depth and the mask are separate limits and both apply. A mask that cannot
cross a separator is not made to by a generous depth: `*.json` with no depth
limit still matches a name, and the depth only says how far down names are
looked for. The two compose rather than override, so neither one has to be
read in the light of the other.

## What is recorded, and why it changes

A run records what it put in the sandbox's profile, beside the sandbox's
bookkeeping and never inside the profile itself — the sandbox may write its
own profile, so a list kept in there would be a list of deletions the sandbox
could edit. The next run reads it to know what to take back.

Today it records entry names, which works because an entry name is also
exactly the path it landed at. With masks that stops being true: one entry can
land as a hundred files, and some of what is under its path is deliberately
not its business.

**The record holds the entries as they were, in their full shape**, rather
than the expanded list of files. Bounded in size, exact about what was asked
for, and — the part that matters — it carries the exclusions forward. When an
entry is removed from the rules file, the next run clears what that entry
brought in *while still sparing what its exclusions protected*. A person who
takes `~/.codex` out of the list has said something about copying, not about
the agent's sessions, and the sandbox should not lose them to a change that
was never about them.

The old records read back unchanged: a file of bare paths is a ktav array of
bare entries, which is measured (probe 3 above) and needs no version field.

## The order of a pass

1. **Cleanup.** The `cleanup:` globs, cleared from the profile.
2. **Forget.** What the recorded entries brought in and the current list no
   longer names, honoring each recorded entry's own exclusions.
3. **Copy.** Each entry in the current list, within its depth, its includes
   and its excludes, against the 64 MB ceiling.
4. **Record.** The current entries, written whatever happened — a copy that
   stopped in the middle still has to be findable next time or nothing will
   ever clear it.

Cleanup runs first so that a rule about what should not be there is applied
before anything decides what to bring in. Forget runs before copy so a name
leaving the list cannot race a name joining it.

## What this is not

Named as firmly as what it is, because each of these is a plausible next step
that would cost something the tool exists to provide.

- **Nothing is ever copied out of a sandbox's profile into the user's.** The
  direction is fixed in the copier, not left to a caller, and no entry shape
  can reverse it. A sandbox able to write back into the files its credentials
  came from could rewrite them.
- **No reparse point is followed, in either direction.** The destination is
  pinned by an `os.Root`; the source skips anything that is neither a plain
  file nor a directory. A link in the user's profile is their arrangement to
  make and not something to copy into a sandbox.
- **No per-project profile sections.** The list is machine-wide, like today.
  What a *project* may write is the `projects:` section's business, and mixing
  the two would make "what is in this sandbox's profile" depend on which
  directory a run started in.
- **No copy-if-newer.** What is refused is still destination-clock-based
  syncing: the destination's timestamps belong to the sandboxed program, and
  skipping a copy because the destination "looks new enough" trusts a value the
  contained thing controls. What that reasoning missed is that the comparison
  never has to read the destination at all. The fingerprint kept in the
  sandbox's bookkeeping, beside the `.copied` record and outside the profile,
  is the SOURCE's size and modification time — both values the sandbox cannot
  forge — and a file is skipped only when its source matches it. The
  destination is only asked whether it still holds what it was left holding,
  which is an ordinary repair, not a judgment about its honesty. The behavior
  change, stated plainly: a sandbox that edits its own copy of a file now keeps
  that edit until the source changes, where every run used to overwrite it.
  That is not a security loss — a sandbox can keep a copy of anything it was
  ever handed — but it is a change. The skip exists because the default grew
  to roughly 2.8 MB across about 250 files, and recopying all of it on every
  run stopped being affordable.
- **No lifting of the 64 MB ceiling** to make a wider default fit. If a
  measured default does not fit under it, that is an answer about the default.
- **No regular expressions, and no negated masks.** `exclude` is the negation,
  and one way to say a thing is enough.
- **No cleanup of the registry hive or the profile service's own directories.**

## Left to measure

Whether the shipped default should name directories with exclusions instead of
the flat file list is not settled here and is not guessable: it depends on what
`~/.codex` minus its sessions actually comes to on a real machine, against the
254 KB the flat list measures now and the 64 MB ceiling. Task #164 counts files
and bytes both ways and decides from the numbers.
