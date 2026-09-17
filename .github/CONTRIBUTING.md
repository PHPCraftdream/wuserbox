# Contributing

## What you need

Windows, and Go as declared in `go.mod`. wuserbox calls the Windows security
APIs directly and its tests create real access control entries, so it does not
build or run anywhere else.

```
go build ./...
go test ./... -count=1
go vet ./...
gofmt -l .
golangci-lint run --config .github/golangci.yml ./...
```

A handful of tests create a local group and therefore skip without
administrator rights. They say so when they skip. To run those too, use an
elevated terminal.

## The boundary tests

The one property this tool exists to provide is that a sandbox cannot delete
or change anything outside what it was handed. Those tests are named one by
one in `.github/workflows/ci.yml`, and the build fails if any of them skips or
if the count stops matching. If you rename one, rename it there too. If you
add a property to the boundary, add its test to that list.

A change to how permissions are decided is not finished until a test fails
without it. The habit here is to prove that: apply the fix, write the test,
then revert the fix and watch the test go red.

## What the comments are for

Comments in this repository say **why**, not what. Most of them exist because
something was measured — an access mask that behaved differently from the
documentation, a refusal that beat a permission whatever the order, a handle
number Windows handed out again. If you find out something about Windows the
hard way, write it down next to the code that depends on it; that is the part
a reader cannot recover on their own.

Keep files under 500 lines and directories under about seven entries. Where
those two pull against each other, the line limit wins, and here is why,
measured in September 2026 when every oversized file in the repository was
split at once.

In Go a directory is a package. An oversized file can therefore only be split
into siblings beside it, which raises the entry count of the very directory
the second rule is about: `internal/policy/profile` went from thirteen entries
to seventeen by obeying the line limit, and there is no arrangement in which
it obeys both. Splitting the package instead would mean exporting what
crosses the new boundary — `walk`, `copiesFile`, `matchMask`, `within`,
`forget` — and those are the internals of a security boundary, deliberately
unreachable from outside this package. A layout rule is not worth an API.

So the entry guideline applies where it costs nothing: documentation
directories, and packages that are genuinely separable on their own merits
rather than to satisfy a count. It does not apply to a Go package that is one
subject. When a directory goes over because a file was split, that is the
rule working, not failing.

One measured exception in the other direction: `docs/checkpoints` is flat and
stays flat however many entries it grows to. The `/checkpoint` and `/resume`
tooling reads that directory non-recursively — `/resume` sorts every `.md` in
it by modification time and picks the first — so grouping the files by month
would hide every existing checkpoint from the tool that exists to read them.

## Commits

One subject per commit, and a message that explains the reasoning rather than
restating the diff: what was wrong, what it cost, and why this is the fix. The
history here is meant to be readable a year later by somebody deciding whether
it is safe to change something.

## Licensing

Contributions are accepted under the same two licenses as the project: MIT or
Apache-2.0, at the user's option, as stated in section 5 of the Apache license
text in [LICENSE](../LICENSE). By opening a pull request you agree to that.

## Security

Do not open a public issue for something that crosses the boundary. See
[SECURITY.md](SECURITY.md).
