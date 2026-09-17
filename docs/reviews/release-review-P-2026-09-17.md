# Release review — `3d03427`

Дата: 2026-09-17  
Объект: полный review wuserbox с приоритетом escapes, ACL/process failures,
data loss и profile copy.

## Verdict

Релиз блокируется. CI зелёный, но подтверждена P0-регрессия в основной
границе: объект, созданный sandbox-процессом, может сохранить право менять
свой ACL после того, как пользователь сузил каталог до `RO` или отозвал грант.

## P0

### P0-1 — sandbox-owned objects bypass later `RO`/revoke

**Evidence.** Defensive probe used the same restricted-token construction as a
real run (`token.AsSandbox`), with no open handles involved:

1. restricted process creates `owned.txt` inside a writable directory;
2. the operator applies the normal `Isolate(..., grant.RO, ...)` narrowing;
3. a new process under the same restricted token is denied an ordinary write;
4. that process can change the file's DACL through owner implicit
   `WRITE_DAC`, grant itself full access, and then rewrite the file.

The observed sequence was: initial write `Access denied`, ACL rewrite succeeds,
subsequent write succeeds. This is the same identity and token shape as the
production account path; the older synthetic probe that used a user-owned
directory was intentionally not used as the finding.

**Impact.** `--ro` and revoke do not reliably take back write access to files
and directories created by the sandbox before the narrowing. This violates the
central boundary guarantee and can leave data writable after the user believes
the grant has been removed.

**Likely cause.** The read-only ACL denies the sandbox group, but the sandbox
account owns objects it created. `OWNER RIGHTS` is currently used for the
process shield, not for sandbox-created filesystem objects. The owner therefore
retains the implicit ability to rewrite the DACL.

**Required acceptance test.** Under a real account on the CI runner, create a
child directory and file from the sandbox, narrow the parent and the child to
RO, revoke them, then attempt DACL changes, ownership changes, overwrite and
delete. The test must verify the original content and ACL remain unchanged.

**Possible fix direction.** Apply an `OWNER RIGHTS` ACE that removes
`WRITE_DAC`/`WRITE_OWNER` from every object created by the sandbox, or arrange
that sandbox-created objects cannot retain the sandbox account as an owner.
The fix must cover files and directories and must preserve ordinary sandbox
operation inside still-writable grants.

## P1

### P1-1 — ordinary `HKCU\Software` is unusable

The current seeded hive grants the sandbox account full access only to the hive
root. The ACEs in `setHiveSecurity` have no container inheritance, so keys made
by the first logon under the root are not accessible to the account later.

The real-account CI measurement records:

- `HKCU` root write: succeeds;
- a key created by the account directly under `HKCU`: succeeds and remains
  writable;
- `HKCU\Software` create/read/write: `Access denied`;
- `HKCU\Software\Classes`: succeeds because it is the profile service's
  separate `UsrClass.dat` hive.

This breaks ordinary programs that store settings below `HKCU\Software`, so
the product is not ready for the stated “any program” promise. The issue is
accurately documented in [limits.md](../limits.md) and the investigation, but
documentation does not make the compatibility problem go away. The likely
implementation change is to add the required registry container inheritance
flags in `setHiveSecurity`, followed by a real-account regression test.

## P2

### P2-1 — real-account coverage still misses sandbox-created descendants

`TestAReadOnlyHandoverHoldsOnTheSecondEntry` is valuable and passes in CI, but
its read-only tree and file are created by the operator before the account is
run. That proves the account cannot modify user-owned objects after RO; it does
not cover objects whose owner is the sandbox account. The P0 test above is the
missing production-shaped case and must be added to the boundary list.

### P2-2 — cleanup family analysis remains a high-risk maintenance area

The earlier variable-width TxR mask bug was fixed by `e33afc5` and regression
coverage was added. The current `families.go` parser now handles GUIDs,
containers and variable TxR indexes, but it is a custom language-intersection
engine. Keep the generated family-width tests and require a regression for each
new Windows transaction-file shape before changing it. This is a coverage and
maintenance risk, not a currently reproduced data-loss defect at `3d03427`.

## P3

### P3-1 — missing referenced security policy file

`.github/CONTRIBUTING.md` links to `SECURITY.md`, but no `SECURITY.md` exists in
the repository. Add the file or remove the broken reference before publishing.

### P3-2 — oversized hive measurement test

`internal/account/ownprofile_hive_test.go` is over the repository's stated
500-line file guideline. It does not block correctness, but should be split
after the security work is complete so the measurement remains maintainable.

## Verification

- Current SHA: `3d034275a1cf8345adc82e10fbca7b84ca1e82a5`.
- CI run `35234580302`: success.
- Boundary step: 45 named tests, 45 PASS, 0 SKIP.
- Local build, vet, formatting and golangci-lint: pass at the reviewed state.
- The new P0 finding was reproduced with fresh processes and no inherited open
  file handle; the synthetic owner's temporary directory used for the probe is
  outside the repository.

## Release decision

Do not release as a security boundary yet. Fix P0-1 and add the real-account
regression first. Treat P1-1 as a release blocker for the advertised arbitrary
program compatibility; until it is fixed, describe wuserbox as experimental
and expect programs that write `HKCU\Software` to fail.
