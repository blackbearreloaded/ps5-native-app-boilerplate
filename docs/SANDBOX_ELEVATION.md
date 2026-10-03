# Lapy sandbox elevation

This optional example is a cooperative client for the official
[PS5-Lapy-JB-Daemon](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon).
The boilerplate does not contain, fork, or rebuild Lapy's kernel backend. It
does not bundle an elevation ELF. Run an upstream Lapy owned-root daemon, then
launch the application.

This replaces the removed boilerplate helpers. The original helper directly
published unowned root-vnode pointers. A later local adaptation copied Lapy's
kernel transaction into a per-app ELF. Both approaches are gone: kernel
ownership and firmware support now have one upstream implementation and one
upstream project to validate.

Lapy currently documents completed console validation on firmware 12.02 only.
Other SDK-supported versions are experimental even when runtime layout checks
pass. Never fall back to a raw-pointer helper when Lapy rejects a target.

## Application API

Compile `examples/sandbox-elevation/src/elevation.cpp` into the application and
include `examples/sandbox-elevation/elevation.hpp`:

```cpp
const auto result = elevation::request(elevation::Capability::filesystem);
if (result == elevation::Status::ok)
{
    // /data write/read was verified; privileged initialization may continue.
}
```

Call it once during single-threaded startup, before creating workers. The
client follows Lapy's cooperative contract:

1. Preopens `/download0/lapy_owned_result` so it remains usable after the root
   change.
2. Calls native `seteuid(geteuid())` to give this process the private credential
   shape required by Lapy.
3. Atomically publishes `{"PID":<getpid()>}` as
   `/download0/elevate_proc`.
4. Polls for elevation by creating, writing, seeking, reading, comparing, and
   removing a PID-specific probe under `/data`, for at most ten seconds.
5. Reports `DATA_OK` and `OPEN_ERRNO` through the preopened result descriptor.
6. Returns `Status::ok` only after the `/data` proof succeeds.

The client does not use disappearance of `elevate_proc` as its success signal.
Path visibility can change with the root transition, and request consumption is
not itself proof of elevation. The real `/data` round trip is the stronger and
portable completion condition; Lapy still removes the request and validates the
preopened result file.

`downloadDataSize` must be positive in `sce_sys/param.json`. A missing daemon,
daemon rejection, or held transaction never authorizes privileged work. Keep
the title alive after a timeout while inspecting the daemon log; if Lapy reports
`daemon_held`, reboot the console before closing or retrying the title.

## Run the upstream daemon

Pin, audit, build, and distribute Lapy separately from each application. Do
not copy its donor or kernel source into an app repository. At the pinned
upstream commit:

```bash
git clone https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon.git
cd PS5-Lapy-JB-Daemon
git checkout 5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad
PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make check
```

Lapy provides two suitable operating modes.

### One-shot lifecycle validation

```bash
python3 tools/build_owned_daemon.py \
  --sdk /path/to/ps5-payload-sdk \
  --logging-client /path/to/ps5log-client \
  --title PPSA99790 \
  --require-client-result
```

Replace `PPSA99790` with the application's exact title ID. Do not use a
wildcard for one-shot mode.

Send `build/owned_root_daemon/lapy-root-daemon.elf` to elfldr before launching
the title. One invocation accepts one cooperative request, checks the client
result, waits for title exit, verifies the root counter returned to its
baseline, then exits. Reuse the built ELF for later invocations; do not rebuild
it between cycles.

This is the preferred qualification mode because every run covers the full
launch -> elevation -> `/data` proof -> title exit -> root-balance lifecycle.

### Resident service

```bash
python3 tools/build_owned_daemon.py \
  --sdk /path/to/ps5-payload-sdk \
  --logging-client /path/to/ps5log-client \
  --service \
  --require-client-result
```

Send `build/owned_root_daemon-service/lapy-root-daemon.elf` to elfldr once per
boot. It watches all `PPSA*` sandboxes and can serve successive cooperative
apps. Run exactly one daemon. For an attended bounded test, invoke upstream's
`tools/build_owned_daemon.py` with `--service --max-requests N`; add
`--require-client-result` to require the application's `/data` proof.

The resident mode is convenient for many apps, but release qualification must
still close every title and independently confirm final reference balance.

Lapy requires its documented `ps5log/1` client and server configuration. Treat
`daemon_start`, `root_layout valid=1`, `roots_committed`,
`donor_balance expected_two=1`, `request_result stage=complete error=0`, and a
balanced final exit as required evidence. `daemon_held` is a failed run even if
the console has not panicked.

## Firmware 6.02 validation result

On 2026-10-03, the exact upstream one-shot daemon at commit
`5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad` was tested on firmware 6.02 with
PS5 Payload SDK v0.40 (`13ccc2d5bf2ac396cdf5007c2b72493cb3d5c8bb`). The
Lapy ELF SHA-256 was
`3e1a101e21b4be242dd65146140985f745e21d8b82532340774800fc6930430a`.

The uninterrupted quick run completed 50/50 functional cycles in 142.93
seconds with 50 unique title PIDs. Every cycle had:

- successful application `/data` write/read proof;
- `request_result stage=complete error=0` and `client_result data_rw=1`;
- a clean `daemon_result stage=complete error=0` and `ps5log/1` BYE;
- root hold/use counters returning from the transferred `56/55` state to the
  same `54/53` baseline after title exit; and
- successful title close and healthy FTP, klog, and elfldr services.

No kernel panic, double fault, or fatal kernel trap was captured. This is a
functional lifecycle pass, not a production safety qualification: klog also
captured 54 user-mode `SIGSEGV` exits from upstream `payload.elf` donor
processes. Fifty-one faulted at `0x1b0`; three used ASLR addresses ending in
`0x1b0`. Lapy's root-balance checks still passed, but any donor fault fails the
strict criterion in this guide.

Therefore firmware 6.02 remains unsupported for production use. Do not enable
elevation by default on it, and do not patch a private copy of Lapy to hide the
diagnostic. Resolve firmware-specific donor release behavior in the upstream
project, then repeat this lifecycle gate. Upstream's documented 12.02 result is
not evidence for other firmware.

## Build and host tests

```bash
make test-elevation
make sandbox-elevation-ffpfsc
```

The first target tests the application-side credential preparation, atomic
request publication, partial writes, data-ready timeout, `/data` proof, and
result reporting. The second builds the `PPSA99790` proof title without an
elevation payload. Host tests cannot establish kernel or firmware safety;
hardware lifecycle testing belongs to the exact upstream Lapy ELF.

## Migration policy for all boilerplate apps

1. Delete every copied or prebuilt `sandbox-elevator.elf`, root-pointer helper,
   donor transaction, and application-local elevation daemon.
2. Keep only the cooperative app client. Call it once before starting threads.
3. Install or launch one independently versioned upstream Lapy build for the
   console environment. Choose one-shot or resident mode operationally; apps do
   not change between them.
4. Proceed only after `Status::ok`. A request file disappearing is not success;
   the app must verify `/data` access.
5. Pin the Lapy commit, payload-SDK commit, logging client, loader, firmware,
   and ELF hash in release records.
6. Qualify each firmware/loader combination with repeated full lifecycle runs.
   Any `daemon_held`, donor crash, root-count drift, title-close failure, loader
   failure, or kernel panic invalidates the run.
7. Update Lapy upstream for kernel behavior changes. Do not maintain another
   kernel implementation in each app or in this template.

## Credits and source reference

The owned-reference design, daemon, donor transaction, runtime guards, and
cooperative protocol belong to
[mpereiraesaa/PS5-Lapy-JB-Daemon](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon).
Credit belongs to Arksama / Team PHU, mpereiraesaa, and the Lapy contributors.
This integration was aligned with upstream commit
[`5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad`](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon/commit/5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad).
Use Lapy under the license in its repository; no Lapy kernel source or binary is
redistributed here.
