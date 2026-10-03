# Owned-reference sandbox elevation

This optional example lets a native application request the filesystem
capability from a bundled helper ELF through an already-running elfldr on
loopback TCP port 9021. The default boilerplate remains sandboxed.

The helper uses the guarded, move-only vnode-reference design from
[PS5-Lapy-JB-Daemon](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon).
It replaces the former boilerplate helper, which copied the system root vnode
address directly into `fd_rdir` and `fd_jdir` without acquiring references.
That old approach could leave two target slots releasing references they never
owned when the title exited, making delayed or cumulative kernel panics
plausible. Do not retain or fall back to the old helper in downstream apps.

This is still experimental kernel-state manipulation. It is materially safer
because it transfers references that native filedescs already own, validates
its assumptions at runtime, and fails closed, but it is not a general proof of
compatibility with every firmware, loader, or process layout.

## Application API

Compile `examples/sandbox-elevation/src/elevation.cpp` into the application and
include `examples/sandbox-elevation/elevation.hpp`:

```cpp
const auto result = elevation::request(elevation::Capability::filesystem);
if (result == elevation::Status::ok)
{
    // Normal sceKernelOpen/read/write calls can now access /data.
}
```

Call it once during single-threaded startup, before creating workers. Keep the
process alive until the request completes. The optional second argument changes
the default helper path, `/app0/sandbox-elevator.elf`.

Only `Status::ok` authorizes elevated work. On any other status, stop privileged
initialization and close the title normally. A timeout can mean that the helper
entered its deliberate held state, so it does not prove that every kernel-side
change was undone.

## Build one helper per title

The helper is bound to one exact `PPSA` title at compile time. Build it with the
same title ID as the application's `param.json`:

```bash
make sandbox-elevation-helper SANDBOX_ELEVATION_TITLE=PPSA12345
```

Package `build/sandbox-elevation/sandbox-elevator.elf` at
`/app0/sandbox-elevator.elf`. A boilerplate-based application can include it by
adding that path to `APP_ROOT_FILES`. The supplied proof title remains:

```bash
make sandbox-elevation-ffpfsc
```

That target uses `PPSA99790` and writes and reopens two proof files under
`/data`. The build validator rejects a helper without the owned-root identity
marker, a helper built for the wrong requested title, malformed ELF section
framing, or trailer bytes that elfldr would mistake for protocol data.

Do not build a wildcard helper and do not accept a title ID or raw kernel value
from the client. A PID and title string are only scope checks; this protocol
assumes an owner-trusted local payload environment.

## Why the owned-reference transfer is safer

A filedesc directory slot owns a vnode reference. Changing its pointer is not
equivalent to acquiring a reference. The helper therefore never manufactures a
system-root reference with a raw pointer assignment.

For each request it:

1. Confirms the SDK supplied a firmware version and the required proc, filedesc,
   prison, and root-vnode symbols.
2. Uses one disposable native `rfork(RFPROC | RFFDG)` child to prove the assumed
   root vnode counter layout. Starting that child must add exactly two hold/use
   references (root and current directory), and reaping it must return both
   counters to their baseline. The bounded probe may retry but never relaxes
   these deltas.
3. Requires the target to have a private filedesc (`fd_refcnt == 1`), one thread,
   a private credential with the expected two references, the expected prison,
   and non-system sandbox roots. It then attaches with `ptrace`, stops the title,
   and takes two stable snapshots before changing state.
4. Applies and reads back the fixed credential profile only after the app's
   native `seteuid(geteuid())` clone has produced a private credential.
5. Starts two additional `RFPROC | RFFDG` donor processes. Each donor owns a
   native system-root reference in its private filedesc.
6. For each target directory slot, first moves the old target reference into an
   empty donor slot, then moves the donor's owned system-root reference into the
   target. The source is cleared before the destination is populated, so an
   interrupted write may strand a reference but cannot publish two owners of one
   reference.
7. Reads back all six transaction slots, reaps both donors through native
   filedesc cleanup, and requires the root vnode counters to equal the original
   baseline plus exactly two: one reference now owned by target `fd_rdir` and one
   by target `fd_jdir`.
8. Only then detaches and resumes the title.

The donor transaction moves both old target references as well. Donor teardown
therefore releases the displaced sandbox roots through the kernel's normal
filedesc path instead of silently leaking them.

## Fail-closed behavior

Before the first directory-slot write, a confirmed failure restores the original
credential, cleans up donors, detaches, and reports an error. Once root ownership
has been touched, an ambiguous write, readback, donor teardown, reference-count,
or detach result enters `daemon_held`: the helper keeps affected processes
stopped and does not let an uncertain owner exit. Recovery from this state is a
console reboot, not an application retry.

This behavior intentionally favors a hung request over a double release and
kernel panic. Check klog for these stages when diagnosing a timeout:

- `root_layout`: disposable donor added exactly two references and returned to
  baseline.
- `target_preflight` and `target_stopped`: private, stable target state.
- `roots_committed`: all moved slots read back correctly.
- `donor_balance expected_two=1`: donors were reaped and exactly two target-owned
  system-root references remain.
- `daemon_held`: state became ambiguous and was deliberately frozen.

There is no legacy fallback. Retrying elevation in the same process after a
timeout is unsupported.

## Transport and lifecycle

1. The app streams `/app0/sandbox-elevator.elf` to elfldr while keeping the TCP
   connection open.
2. The app sends one `request` containing its PID and the filesystem capability.
3. After validating the PID/title, the helper sends `prepare`. The app calls
   native `seteuid(geteuid())` and replies `prepared`.
4. The helper verifies the credential clone, stops the target, performs the
   guarded elevation, sends one terminal `response`, and exits.

Both endpoints use five-second socket timeouts and handle partial transfers.
There is one request per helper invocation and no automatic resubmission. The
title retains its new credential and owned root references until it exits; the
one-shot helper cannot observe the final title-exit reference balance, so that
must be covered by hardware lifecycle testing.

## Version 1 wire format

The client ABI did not change. Every message is exactly 24 bytes, little-endian.
`protocol.hpp` is the C++ definition and `payload/elevation_protocol.h` is its C
counterpart; host tests verify the golden bytes.

| Offset | Type | Field |
| --- | --- | --- |
| 0 | u32 | Magic `0x31564c45` (bytes `ELV1`) |
| 4 | u16 | ABI version `1` |
| 6 | u16 | Message size `24` |
| 8 | u32 | Kind: request `1`, prepare `2`, prepared `3`, response `4` |
| 12 | u32 | Capability: filesystem `1` |
| 16 | u32 | Positive application PID, at most `INT32_MAX` |
| 20 | u32 | Status; request and prepare must use `0` |

| Status | Value | Meaning |
| --- | --- | --- |
| `ok` | 0 | Update applied and ownership checks passed |
| `invalid_request` | 1 | Malformed message or unexpected phase |
| `unsupported_version` | 2 | Incompatible ABI version |
| `unsupported_capability` | 3 | Capability has no supported implementation |
| `target_mismatch` | 4 | PID/title mismatch or target disappeared |
| `unavailable` | 5 | Required kernel state or layout unavailable |
| `prepare_failed` | 6 | Native credential preparation failed |
| `apply_failed` | 7 | Guarded update failed before safe completion |
| `rollback_failed` | 8 | Retained for version 1 compatibility; ambiguous ownership is held instead |
| `transport_error` | 9 | Socket or transfer failed |
| `protocol_error` | 10 | Client received an invalid or mismatched reply |

Requests carry no kernel pointers, offsets, credential masks, or authority IDs.

## Tests and firmware validation

```bash
make test-elevation
make lint test
make sandbox-elevation-helper SANDBOX_ELEVATION_TITLE=PPSA99790
make sandbox-elevation-ffpfsc
```

Host tests cover client framing, partial transfers, the move-only two-root
transaction, injected read/write failures, absence of duplicate ownership, and
strict vnode-counter deltas. They cannot establish PS5 runtime compatibility.

The Lapy reference implementation documents completed console validation on
firmware 12.02. This boilerplate integration completed two
launch/elevate/write/reopen/close cycles on firmware 6.02 on 2026-10-03. That is
an integration smoke test, not a soak result. Previous testing of the removed
raw-pointer helper does not validate this backend.

Before shipping on a firmware/loader combination, run repeated full lifecycle
cycles, including normal close, forced close during preparation, and relaunch.
Record the helper hash, SDK commit, loader version, firmware, exact pass count,
klog stages, and whether loader health remained intact. Treat a new SDK offset
set or loader as a new validation target.

## Migration policy for all boilerplate apps

1. Update to this helper and keep the existing `elevation::request` client API.
2. Remove copied legacy helper sources and prebuilt `sandbox-elevator.elf` files.
3. Build a fresh helper for each app's exact title ID; never share a helper
   binary between titles.
4. Package the freshly validated helper with the app instead of downloading or
   caching it globally.
5. Elevate once, at single-threaded startup. Do not add a resident elevation
   service or retry loop to individual apps.
6. Keep app-specific privileged operations above this common API. Changes to
   credential or vnode ownership belong in the shared helper and require host
   fault tests plus hardware lifecycle testing.
7. If the helper returns anything but `ok`, skip privileged work. If it times
   out after the target was stopped, reboot the test console before another run.

## Credits and source reference

The owned-root design and move-only donor transaction are adapted from
[mpereiraesaa/PS5-Lapy-JB-Daemon](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon)
at upstream commit
[`5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad`](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon/commit/5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad).
Credit belongs to Arksama / Team PHU, mpereiraesaa, and the Lapy contributors.
The retained upstream MIT license is in
`examples/sandbox-elevation/payload/LAPY_LICENSE.txt`; adapted source files are
distributed under this repository's GPL-3.0-or-later terms while preserving the
upstream copyright and notice.
