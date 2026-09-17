# Working on wuserbox

The layout, how the tests are run, and how a release is cut. The rules a
change is held to are in [CONTRIBUTING](../.github/CONTRIBUTING.md).

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

