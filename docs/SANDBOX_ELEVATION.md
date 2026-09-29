# elfldr elevation protocol

This optional example lets a native application request a named capability from
a bundled helper ELF. It uses an already-running, compatible elfldr on loopback
TCP port 9021. No elfldr or kstuff modifications are required.

The only implemented capability is `elevation::Capability::filesystem` (ID 1).
The default boilerplate remains sandboxed.

## Application API

Compile `examples/sandbox-elevation/src/elevation.cpp` into your application and
include `examples/sandbox-elevation/elevation.hpp`:

```cpp
const auto result = elevation::request(elevation::Capability::filesystem);
if (result == elevation::Status::ok)
{
    // Normal sceKernelOpen/read/write calls can now access /data.
}
```

Call during single-threaded startup, before starting workers. Keep the process
alive until the request completes. A second argument can override the default
bundled helper path, `/app0/sandbox-elevator.elf`. Build and package the matching
helper; an ELF compiled for an earlier protocol is incompatible.

The supplied helper accepts only `PPSA99790`. For another app, update
`target_title_id` in `payload/main.cpp` together with the app's `param.json`,
and rebuild. The PID in a request must also resolve to that title. A PID or
title string is not authentication: this protocol assumes an owner-trusted
payload environment, and the helper is not an arbitrary-process service.

## Transport and lifecycle

1. The app opens `/app0/sandbox-elevator.elf` and streams its bytes to elfldr.
2. elfldr consumes the ELF using its section-table extent and gives the existing
   connection to the helper as stdin/stdout. The app keeps the socket open.
3. The app sends `request` with its PID and one capability ID. The helper rejects
   invalid headers, versions, kinds, statuses, capabilities, and target identity.
4. After snapshotting the target, the helper replies `prepare`. The app calls
   native `seteuid(geteuid())` and replies `prepared`. The helper verifies that
   the same process now references a different credential with unchanged values.
   Failure to obtain private credentials ends the request without elevation.
5. The helper applies the filesystem profile to the private credential and
   filesystem roots, then reads every changed field back. Failed updates trigger
   restoration and verification of the original values.
6. The helper sends one terminal `response` and exits. Only `Status::ok` lets the
   example write, close, reopen, and byte-verify `/data/hello-from-sandbox.txt`
   and `/data/PPSA99790-poc.txt`. These two example files are overwritten on each
   successful run; the second includes a build tag and the application PID.

There is one capability request per helper invocation. The helper exits after
the response. The example calls the API once at startup; each additional API call
launches another helper. Elevation remains with the app
process until it exits, so no helper needs to wait for app closure.

No additional listener, daemon, JSON parser, or runtime registration mechanism is
needed. Diagnostics go to klog; stdout carries protocol bytes only.
Each socket operation has a timeout,
defaulting to five seconds. Tune `wire::io_timeout_us` in `protocol.hpp` and rebuild
both endpoints for slower hardware. Partial transfers are handled; EOF, timeout,
or interruption ends the attempt. There is no automatic resubmission.

The build checks that the helper ELF ends exactly at its section table and that
all stored sections fit in the file. Extra ELF trailer bytes would otherwise be
misinterpreted as protocol bytes by the helper. Do not append or independently
postprocess the packaged ELF after this check.

## Version 1 wire format

Every message is exactly 24 bytes, little-endian. `protocol.hpp` is the shared
definition and verifies its layout at compile time.

| Offset | Type | Field |
| --- | --- | --- |
| 0 | u32 | Magic `0x31564c45` (bytes `ELV1`) |
| 4 | u16 | ABI version `1` |
| 6 | u16 | Message size `24` |
| 8 | u32 | Kind: request `1`, prepare `2`, prepared `3`, response `4` |
| 12 | u32 | Capability: filesystem `1` |
| 16 | u32 | Positive application PID, at most `INT32_MAX` |
| 20 | u32 | Status; request and prepare must use `0` |

Replies echo the requested capability and PID. The client checks their header,
identity, kind, and status before advancing. A success response before the
preparation handshake is invalid. Requests carry no kernel pointers, firmware
offsets, raw capability masks, or authority IDs.

| Status | Value | Meaning |
| --- | --- | --- |
| `ok` | 0 | Update applied and verified |
| `invalid_request` | 1 | Malformed message or unexpected phase |
| `unsupported_version` | 2 | Incompatible ABI version |
| `unsupported_capability` | 3 | Capability has no supported implementation |
| `target_mismatch` | 4 | PID/title mismatch or process changed during preparation |
| `unavailable` | 5 | Helper file, payload context, or required kernel state unavailable |
| `prepare_failed` | 6 | Native credential preparation failed or was not verified |
| `apply_failed` | 7 | Update failed; original values were restored and verified |
| `rollback_failed` | 8 | Restoration could not be verified; process state is uncertain |
| `transport_error` | 9 | Socket or transfer failed; the terminal result may have been lost |
| `protocol_error` | 10 | Client received an invalid or mismatched reply |

After any nonzero result, skip elevated work and close the title. A lost reply
does not prove the update was undone. The example reports the numeric status and
remains idle for normal shell-mediated closure instead of polling `/data` forever.

## Adding a capability

1. Assign a new, never-reused numeric ID in `Capability` and explicitly allow it
   in `wire::validate`. IDs represent individual requests, not a bitmask.
2. Add a handler and a case in `handle_request`'s capability switch. Keep privilege
   policy inside the helper; callers must not supply raw credentials or addresses.
3. Give the handler checked updates, verification, failure handling, and a focused
   regression in `tests/test_elevation.cpp`. Validate its actual operation on the
   intended firmware before claiming support.
4. Document its effects and interaction with previously granted capabilities.
   Retain version 1 only if the existing frame and handshake semantics are unchanged;
   incompatible framing or semantics require a new version and matching endpoints.

An old helper explicitly rejects an unknown ID. The fixed-profile idea and native
credential preparation are informed by
[kstuff-lite PR #73](https://github.com/EchoStretch/kstuff-lite/pull/73).
Its process-memory and debugging profiles are not implemented here.

## Filesystem scope and validation

The filesystem handler retains the proof's root/system-authority/full-capability
recipe and also clears the saved group ID. It changes filesystem root/jail vnode
references; it does not replace `cr_prison`. **Filesystem is the only exposed
protocol capability, not an enforced filesystem-only privilege boundary.** This
recipe grants broad process privileges; it does not restrict access to `/data`,
remount read-only filesystems, or guarantee access to every path. Test the actual
paths your application needs, including `/app0` and `/download0` after elevation.

The SDK selects firmware offsets during payload startup and rejects unsupported
firmware. Native same-UID credential preparation can also fail on a given loader
or firmware; the helper refuses to edit a credential that did not change. External
kernel updates cannot prevent the process being killed concurrently. Keep this
operation at startup and do not close the title during the handshake.

```bash
make test-elevation
make lint test
make
make sandbox-elevation-ffpfsc
```

The image is `dist/PPSA99790.ffpfsc`. CI checks the host protocol/rollback regression
and builds the example. Host tests mock native calls and inject partial writes;
they cannot establish PS5 runtime compatibility.

The maintainer reported successful console tests of this versioned implementation
on firmware **6.02 and 12.70** on 2026-09-29, using the existing elfldr-based setup.
Exact loader versions were not recorded here; these results do not establish
compatibility with every loader or firmware combination.

For future hardware regressions, check the success notification, both files' exact
contents and current PID, normal title closure, and continued loader service health.
The proof marker defaults to `tag=poc_run`; use
`make sandbox-elevation-ffpfsc APP_DEFINITIONS=POC_RUN_TAG=my_run` to distinguish a
new build from a previous run. Files remain after the app exits; their existence
alone does not prove the latest request succeeded.
