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
4. Waits up to ten seconds for daemon consumption.
5. Creates, writes, seeks, reads, compares, and removes a PID-specific probe
   under `/data`.
6. Reports `DATA_OK` and `OPEN_ERRNO` through the preopened result descriptor.
7. Returns `Status::ok` only after the `/data` proof succeeds.

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

## Build and host tests

```bash
make test-elevation
make sandbox-elevation-ffpfsc
```

The first target tests the application-side credential preparation, atomic
request publication, partial writes, acknowledgement timeout, `/data` proof,
and result reporting. The second builds the `PPSA99790` proof title without an
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
