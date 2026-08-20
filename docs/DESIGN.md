# DESIGN — why it's built this way

## The TCC problem, and the ssh-to-localhost pattern

macOS TCC (privacy protection) blocks launchd-spawned processes from reading
protected locations: Desktop, Documents, Downloads, and **removable volumes**.
This was proven empirically during development: a LaunchAgent running
`/bin/bash` got "Operation not permitted" on `ls`/`open`/`rsync` against
`~/Desktop`, while `~/Library` read fine. If your backup source is a protected
folder — and "my Desktop" or "my project tree" usually is — a conventional
launchd backup job **cannot work**.

`sshd` *can* hold that access: grant Full Disk Access to Remote Login once,
and every child of sshd inherits it.

So the schedule is:

```
launchd ──▶ ssh -i <dedicated key> localhost <mode> ──▶ sshd ──▶ forced command
                                                              └─▶ snapshot-dispatch ──▶ snapshot
```

The same pattern runs the replica job on the archive host, where launchd
cannot open USB volumes for the same reason.

Two properties fall out of this, one needed and one delightful:

1. **Access** — the job runs as a child of sshd with Full Disk Access, so it
   can actually read the source and the DAS volumes.
2. **Containment** — because the key's `authorized_keys` entry is
   `restrict,command="...snapshot-dispatch"`, the transport that *grants*
   access is also a closed allowlist. The mode string arrives in
   `SSH_ORIGINAL_COMMAND` and is matched against `snap|vault|both|probe`;
   everything else is refused (exit 77) and logged. The scheduling credential
   cannot be repurposed to delete anything.

## Why two legs in two formats

- **Snap leg** (rsync hardlink snapshots): browsable, deduplicated, instant
  single-file restore, cheap daily history. Its weakness: it lives on one
  filesystem, and rsync trees are vulnerable to fs-level accidents.
- **Vault leg** (tar.zst + sha256): one opaque verified blob per day on
  *different hardware*, immune to tree-level tampering, trivially portable.
  Its weakness: no dedup, coarse restore granularity.

Different formats, different hardware, different failure modes — that's the
point. Run both when you can.

## Verification philosophy

Trust nothing you didn't check this run:

- `zstd -t` before shipping an archive (a truncated tar still hashes
  consistently — integrity must be checked *before* the hash becomes the
  reference).
- sha256 comparison after landing (per-OS tooling: `sha256sum`/`shasum` on
  POSIX, `certutil` on Windows).
- rsync exit-code discipline (rc=24 "files vanished" is the one benign case on
  a live tree; anything else fails the run).
- Free-space floor measured **on the destination volume** (`df` of the DAS
  path — not the archive host's boot disk).
- Deep-verify on the archive host proves primary == mirror.
- The probe mode exists so the *transport itself* is testable read-only at any
  time: source readability (the three TCC gates), tool availability, target
  reachability.

## Single-machine mode

Set `SNAP_SSH="localhost"` and attach both drives locally. The forced-command
localhost hop is already how scheduling works, so nothing else changes: the
same containment, the same probe, the same replica between the two attached
drives. You lose machine-level separation (see SAFETY §6) but keep every
other guarantee — and it's a one-liner to point at a real archive host later.

## The monitor shows liveness, not capacity

A 14 TB drive holding 15 GB of perfectly healthy snapshot history reads
**0% used, free space frozen** on any percentage display — indistinguishable
from a dead pipeline. The monitor therefore leads with numbers that *move*:
per-drive fill bars (with a minimum visible sliver for any nonzero usage),
used-bytes at GB precision, **last-snapshot age**, **last-check age**, and
primary/mirror sync state.

## Roadmap

- **Source-manifest verification** — the writer emitting a per-run manifest
  (paths, sizes, hashes) at the source, reconciled on the archive host, so
  "the snapshot is complete relative to what the source held" is *proven*,
  not inferred. Today that leg of the triangle (replica==primary is verified;
  primary==source is not) is the known gap.
- Linux-source scheduling templates (the scripts are portable bash+rsync
  already; only the launchd packaging is macOS-specific).
