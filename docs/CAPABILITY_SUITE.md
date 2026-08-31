# Elevated-capability validation suite

This optional suite accompanies the caller-only kstuff proposal in
[blackbearreloaded/kstuff-lite#1](https://github.com/blackbearreloaded/kstuff-lite/pull/1).
The normal boilerplate application remains sandboxed.

Start with the [proof-application overview](../examples/README.md) for the
plain-language presentation. This document records the protocol, evidence,
and technical limits behind it.

## Build

Build every application image and the shared owned-process helper:

```sh
make capability-examples
```

The individual targets are:

```sh
make self-elevation-ffpfsc
make process-memory-ffpfsc
make system-capabilities-ffpfsc
make ptrace-ffpfsc
make process-memory-helper
```

The resulting FFPFSC images use the committed development titles
`PPSA99792` through `PPSA99795`. The helper is written to
`examples/process-memory/helper/g2-process-helper.elf`.

## Request ABI

The apps use kstuff's existing `getppid` bridge. Operation `7` accepts a
fixed magic, ABI version `1`, and one predefined profile:

| Profile | Authority | Intended proof |
| --- | --- | --- |
| `1` | system | Data access, mount, and privileged-device operations |
| `2` | coredump | Platform `mdbg` access to one explicitly owned helper |
| `3` | debug | Platform `ptrace` access to one explicitly owned helper |

Operation `8`, selector `1`, returns only the calling process's credential
authority ID. It accepts no address and performs no kernel write. Both
operations derive the target process from the current syscall thread; the ABI
accepts no PID, kernel pointer, authority value, capability mask, or structure
offset.

## Coverage

| Goal | Application | Bounded acceptance test |
| --- | --- | --- |
| G1 kernel inspection | `self-elevation` | Read the caller's kernel-resident authority ID before and after profile 1 |
| G2 process memory | `process-memory` | Read, replace, verify, restore, and independently confirm one helper sentinel |
| G3 mount | `system-capabilities` | Mount procfs below `/data`, read it, unmount it, and remove the directory |
| G4 privileged device | `system-capabilities` | Open and immediately close `/dev/mdctl`; issue no ioctl or write |
| G5 networking | `system-capabilities` | Create and close a raw ICMP socket; transmit no packet |
| G6 debugging | `ptrace` | Attach, read, replace, verify, restore, and detach from the owned helper |

`/dev/kmem` and `/dev/mem` return `ENOENT` on the tested environment. G1
therefore uses kstuff's bounded caller-authentication read instead of exposing
an arbitrary kernel-memory primitive.

The G2 `mdbg` wrapper intentionally follows the public SDK ABI: the remote
address remains in the source field and the local buffer remains in the
destination field for both read and write operations; the operation number
selects direction.

## Console order

Load the matching kstuff build once, then run each title separately:

1. Run `PPSA99792` and retrieve `/data/self-elevation-validation.txt`.
2. Send `g2-process-helper.elf` to elfldr, run `PPSA99793`, and retrieve
   `/data/g2-process-memory-result.txt` plus
   `/data/g2-process-helper-result.txt`.
3. Run `PPSA99794` and retrieve
   `/data/g3-g5-system-capabilities-result.txt`.
4. Send a fresh helper, run `PPSA99795`, and retrieve
   `/data/g6-ptrace-result.txt`.

Fully close each title before starting the next. The helper and every probe
operate only on test-owned state and restore or remove what they change.

## Hardware evidence

The complete suite passed on firmware 6.02 with one kstuff load:

| Goal | Result |
| --- | --- |
| G1 | Caller authority changed from `4400001084c2052d` to `4801000000000013` |
| G2 | Helper sentinel replaced, read back, restored, and independently confirmed |
| G3 | procfs mounted, read, unmounted, and cleaned up |
| G4 | `/dev/mdctl` denied before elevation and opened/closed afterward |
| G5 | Raw ICMP socket creation succeeded before and after elevation; no traffic sent |
| G6 | Owned helper attached, read, modified, verified, restored, and detached |

All four titles closed normally, ShadowMount released their runtime layers,
and FTP `2121`, klog `3232`, and elfldr `9021` remained responsive. Profile 1
and the original self-elevation acceptance path were also validated on
firmware 12.70. The complete G1-G6 suite has not yet been rerun there.

## Limits

- This is not a standalone exploit; compatible kstuff must already be active.
- Whitelisted firmware means source-level layout coverage, not hardware proof.
- G5 proves raw-socket availability, not that profile 1 grants it: firmware
  6.02 already allowed the socket in the sandbox control.
- G6 verifies restoration and detach from the tracing app because the traced
  helper is stopped while its memory is changed.
- No probe changes console settings, sends network traffic, issues privileged
  device commands, or exposes a general kernel-memory API.
