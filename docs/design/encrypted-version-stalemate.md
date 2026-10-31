# Design: version stalemate on untrusted devices (#9884)

Status: implemented, tested in one real setup, 2026-10-31. Fork
`sj14/syncthing`, branch `fix/encrypted-version-stalemate`.

## Summary

An untrusted device (folder type `receiveencrypted`) can keep a file version
forever that the trusted devices have already replaced
([#9884](https://github.com/syncthing/syncthing/issues/9884)). In this design
the trusted devices detect such a stuck file and resolve it themselves: they
create a successor of the current version whose fake version is greater than
the one the untrusted device holds. All trusted devices compute exactly the
same successor, so they never create conflicting versions among themselves.

The untrusted device, the fake version format, the fixed modification time and
the protocol stay unchanged. Only the trusted devices need the update.

## Problem and cause

The untrusted device only knows a fake version: the sum of all real counters.
When this sum gets smaller, the untrusted device considers its old version
newer and stops pulling.

**Symptom:** The trusted devices show the untrusted device as incomplete, e.g.
99 % with 7 items needed. The untrusted device itself is `idle` and needs
nothing. The current workaround is to remove the folder on the untrusted
device, delete its data and let it download everything again. Touching the
file on a trusted device also helps sometimes, as reported in the issue.

**Mechanism:**

1. `encryptFileInfo` (`lib/protocol/encryption.go`) sends the version
   `{1: sum of all real counters}` and the fixed modification time
   `1234567890`.
2. A counter is set to `max(old+1, now)` on every change
   (`Vector.updateWithNow` in `lib/protocol/vector.go`), so it is effectively
   a Unix timestamp.
3. A device that is re-added with an empty database rescans a file and creates
   `{A: now}`. Its sum is about half the sum of an older version
   `{A: t1, B: t2}`.
4. The trusted devices settle on the new version. The untrusted device compares
   the fake versions only, considers its own one greater and keeps it.
5. The trusted devices decrypt the index of the untrusted device, see the old
   real version there and report it as incomplete forever.

**Observed** on 2026-10-31 in two folders on a self-hosted untrusted device:
the global versions were single counters from a rescan, e.g.
`<device>:1793443144`. After a reset of the folder on the untrusted device
both sides reported 100 %.

## Requirements and constraints

- **Untrusted device specification**
  ([`specs/untrusted.rst`](https://github.com/syncthing/docs/blob/main/specs/untrusted.rst)):
  the untrusted device must *not* observe "file modification time,
  permissions, or modification history (version vectors)". It may observe
  file sizes and "which parts of files are changed by the other devices and
  when". The fixed modification time follows from this.
- **Determinism:** the fake version must be identical on all trusted devices
  for the same real version, otherwise pulling and remote completion on the
  untrusted device break (#7533, commit `0dcd9794d`).
- **No data loss:** an untrusted device is often used as a backup. It may hold
  the only copy of the newest version, and must never discard it based on
  incomplete information.
- **Compatibility:** no protocol change if possible, so that devices with
  older versions keep working.
- **Contribution policy**
  ([`CONTRIBUTING.md`](https://github.com/syncthing/syncthing/blob/main/CONTRIBUTING.md)):
  no contributions that are "wholly or mostly AI generated", and no unsolicited
  pull requests from new contributors. The approach has to be proposed in the
  issue first; the code has to be written by a human.

## Rejected approaches

| Approach | What it does | Why rejected |
| --- | --- | --- |
| Two-counter fake version `{0: max, 1: sum}` | A real successor stays strictly greater; on concurrent fake versions the highest counter (newest change) wins | Trusted devices decide conflicts by real modification time first, so the two can still disagree, e.g. when the newer change has the older modification time. Depends on correct clocks. Protocol change with a mixed-version transition. |
| Real version vector and real modification time in the fake FileInfo | The untrusted device uses exactly the same ordering as the trusted devices | Violates the specification: it reveals the modification history and the modification times to the untrusted device. |
| Untrusted device defers to the trusted devices (local flag, its own entry never wins) | The untrusted device takes over any valid version a trusted device announces | Can lose data. The untrusted device cannot tell whether the trusted devices have settled or one of them just introduced a concurrent version. Example: it holds the only copy of the newest version B, a restored device announces an old copy A; it replaces B with A while the restored device tries to fetch B from it. |

No encoding of the fake version alone can reproduce the decisions of the
trusted devices without leaking information. The decision has to stay with
the trusted devices, which have the full information.

## Chosen approach

A trusted device knows both sides: its own version L, which is the global
version, and the real version X of the untrusted device, which it stores
decrypted from the untrusted device's index. So it can detect the stalemate
exactly:

- the untrusted device needs the file (its version X differs from the global
  version L, and X is not invalid), and
- `sum(L) <= sum(X)`: the fake version of L is not greater than the fake
  version the untrusted device already has, so it will never pull L.

In that case the trusted device writes a successor L' of L that only differs
in its version vector: it adds or raises a counter for a fixed pseudo device
ID `P`, so that `sum(L') = sum(X) + 1`. Data, blocks, modification time and
`ModifiedBy` stay unchanged. L' is a strict successor of L, so all devices
accept it without a conflict, and its fake version is greater than the one of
X, so the untrusted device pulls it.

**Determinism:** L' only depends on L and X. All trusted devices that have L
and see the same X compute the identical L'. Their versions are equal, so they
never conflict among themselves.

**No loop:** after the bump `sum(L') > sum(X)`, so the condition is false
until the untrusted device announces a different version.

**No data loss:** the untrusted device only takes a version that a trusted
device, knowing both versions, has decided it needs. This is the same as for
any other version update today.

### Value of the pseudo counter

Let `rest = sum(L) - L[P]`. The new value is
`L'[P] = max(L[P] + 1, sum(X) - rest + 1)`. Only the second term changes the
outcome, the first one keeps the counter strictly increasing. The value can be
larger than the current Unix time; version vectors only require counters to
increase, so this is valid. `P` is a constant that is not the short ID of a
real device.

### Where it runs

On the trusted device, in the index handler for the untrusted device
(`lib/model/indexhandler.go`). The handler knows the folder, the remote device
and the database, and has the folder runner for writing:

1. **At start:** a sweep over all files the untrusted device needs
   (`AllNeededGlobalFiles(folder, device, …)`). This also resolves files that
   were already stuck before the update, so no migration is needed.
2. **After receiving an index batch** from the untrusted device: check the
   received files.
3. **After sending an index batch** to the untrusted device: check the sent
   files, because the stalemate typically arises when the trusted device's own
   version changes.

The check only runs if the remote device is untrusted for this folder, and
only on folder types that may announce versions (`sendreceive`, `sendonly`).
The bump is written through the folder runner, like any other local update,
so it gets a new sequence number and is sent to all devices.

### Changes

1. **`lib/protocol/encryption.go`:** `encryptedVersionValue` holds the sum
   formula used by `encryptFileInfo`; `EncryptedSuccessor` computes the
   successor from it.
2. **`lib/model/indexhandler.go`:** for untrusted remote devices, the handler
   schedules the check for the needed files at start, for received files and
   for sent files.
3. **`lib/model/folder.go`:** `ScheduleEncryptedSuccessors` queues the paths,
   like `ScheduleForceRescan`. The folder's main loop handles them in
   `handleEncryptedSuccessors`, so the write never runs in parallel to its
   scanner or puller. It re-checks that the local file is the global one and
   writes the successor through `updateLocals`.

### Size

About 120 lines of code and 150 lines of tests.

## Conflict copies on the untrusted device

Fake versions stay a single counter and are always comparable. The untrusted
device never sees concurrent versions, so the conflict copy rule in
`moveForConflict` that was drafted for the rejected approaches is not needed.
It has been removed from the branch again.

## Compatibility

- **Untrusted device:** unchanged, no update needed.
- **Trusted devices with an older version:** they receive the successor as an
  ordinary version update. It is enough if one trusted device that has the
  global version runs the new code.
- **Untrusted devices from before 2021** had fake versions based on the
  current time in nanoseconds (before commit `0dcd9794d`). For files that
  still carry such a fake version the bump is not large enough. Nothing loops,
  these files just stay stuck as today.

## Remaining risks and open questions

- **Different views of X:** two trusted devices that saw different versions of
  the untrusted device can compute different successors. Those conflict once,
  are resolved like any conflict (equal modification time, then device ID)
  and converge after the next index exchange. No data changes, only versions.
- **Cost:** the checks after sending and receiving need one database lookup
  per file in the batch. The sweep at start iterates all files the untrusted
  device needs.
- **Pseudo device ID in version vectors:** it shows up in the real version of
  bumped files, e.g. in the GUI. It has to be a value that no real device can
  have.
- **Maintainer acceptance:** writing a version without a local change is new
  behaviour and needs agreement in the issue first.

## Tests and validation

- **Version computation** (`lib/protocol` or `lib/model`):
  - `sum(L') = sum(X) + 1`, and L' is `Greater` than L.
  - The same input gives the same output (determinism).
- **Index handler** (`lib/model`):
  - The reset case: an untrusted device with a higher sum gets a bump.
  - No bump if `sum(L) > sum(X)`, if the remote is trusted, if the local file
    is not global, or if X is invalid.
  - No second bump after the first one.
  - The sweep at start finds already stuck files.
- **Reproduction:** the untrusted device pulls the version the trusted devices
  settled on, compared through `encryptFileInfo`.
- **Real run:** a self-built trusted device and an unchanged untrusted device.

Implemented so far:

- `TestEncryptedStalemate` (`lib/protocol`) reproduces the problem. Without
  the fix it fails with `offered fake version AAAAAAA:2500, it has
  AAAAAAA:3000`.
- `TestEncryptedSuccessor` (`lib/protocol`) covers the version computation.
- `TestEncryptedSuccessors` (`lib/model`) covers writing the successor and
  the trigger on a received index.

Not covered by a test yet: the triggers at start and on sending.

### Real run, 2026-10-31

Setup: an untrusted device on v2.1.3, unchanged. One trusted device ran a
build of this branch instead of v2.1.3; the database schema and the config
version are the same in both, so switching back and forth is safe. The other
trusted devices were offline.

| | Before | After |
| --- | --- | --- |
| Untrusted device as seen by the trusted device | 99 %, 4 items needed | 100 % |
| Trusted device as seen by the untrusted device | 100 % | 100 % |
| Untrusted device itself | idle, nothing needed | idle, nothing needed |

- The stalemate had occurred on its own, not as a constructed reset case.
- Within seconds of the start, the trusted device wrote a successor for
  exactly the 4 stuck files (counter `ffffffffffffffff`), and the untrusted
  device pulled them. Afterwards both devices had the identical version.
  This is the trigger at start, so that path is covered by the real run.
- The real versions had the shape `<device>:<t>, ffffffffffffffff:<v>`. For
  one file `v` was about four times the current Unix time, because the
  untrusted device held a version with several counters. This is expected.
- No warnings or errors in the log of the build.
- Afterwards the trusted device went back to v2.1.3, which handles the
  successor versions as ordinary versions.
