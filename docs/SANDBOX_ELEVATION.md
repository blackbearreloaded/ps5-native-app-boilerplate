# Lapy sandbox elevation

This optional example embeds the exact-title one-shot helper from upstream
[PS5-Lapy-JB-Daemon](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon).
The boilerplate does not fork or reimplement Lapy's kernel backend. Its build
fetches a pinned upstream commit, invokes Lapy's own `owned-helper` target,
checks the generated manifest and packages the resulting ELF and MIT license.

The old boilerplate raw-pointer helper and its later copied Lapy backend remain
deleted. Kernel ownership, runtime layout checks and firmware behavior stay in
one upstream implementation.

## Build integration

Set `APP_LAPY_HELPER=1` for an application that compiles the client:

```bash
APP_SOURCE_DIR=examples/sandbox-elevation/src \
APP_PARAM=examples/sandbox-elevation/sce_sys/param.json \
APP_SCE_SYS=sce_sys APP_ASSETS= APP_LAPY_HELPER=1 \
bash tools/build.sh Ffpfsc
```

Or build the included proof title:

```bash
make sandbox-elevation-ffpfsc
```

The helper title is read from the selected `param.json`; wildcard helpers are
not built. The package contains:

```text
lapy.elf
lapy-manifest.json
licenses/Lapy-MIT.txt
```

The build verifies the manifest schema, exact title, one-request helper mode,
ELF and protocol hashes, and `root_layout_probe_retry` feature before copying
those files. Lapy, its `ps5log` build input and the compatible Payload SDK are
cached under ignored `.deps/lapy/`.

## Application API

Compile `examples/sandbox-elevation/src/elevation.cpp`, keep
`elevation.hpp` and `protocol.hpp` beside it, and call the client once during
single-threaded startup:

```cpp
const auto result = elevation::request(elevation::Capability::filesystem);
if (result == elevation::Status::ok)
{
    // /data write/read was verified; privileged initialization may continue.
}
```

`elevation::path()` reports `existing`, `resident`, `helper`, or `none` for
diagnostics.

The runtime sequence is:

1. Probe `/data`; return immediately when access already exists.
2. Publish the cooperative resident request through
   `/download0/elevate_proc` and wait 1.5 seconds.
3. If a resident service claimed the marker, never launch a second helper for
   that title launch.
4. Otherwise cancel the marker, observe one final grace interval, stream
   `/app0/lapy.elf` to the local ELF loader on TCP port 9021 and complete
   upstream's request/prepare/prepared/response exchange on that connection.
5. Return `Status::ok` only after creating, writing, reading, comparing and
   removing a PID-specific probe under `/data`.

The jailbreak environment must provide the local ELF loader on port 9021 when
a resident Lapy service is not already running. `downloadDataSize` must be
positive in `sce_sys/param.json`. A missing loader, rejection, timeout or
failed `/data` proof never authorizes privileged work.

## Pinned upstream inputs

`tools/build-lapy-helper.py` pins:

- mpereiraesaa's Lapy commit
  [`5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad`](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon/commit/5b8397b9f2b5f12a7bc2f9c8745a00d1c2dd01ad);
- official PS5 Payload SDK v0.40, used only for the helper because v0.41
  changed the credential-attribute API; and
- the pinned `ps5log/1` header used by upstream's build.

The normal boilerplate application build continues to use Payload SDK v0.42.
The two toolchains are deliberately separate.

## Validation and firmware caveats

Run the host exchange tests with:

```bash
make test-elevation
```

The tests cover resident success, resident claim without fallback, partial
socket transfers, helper rejection, client preparation failure, corrupt data
proof and the fixed 24-byte wire ABI. Host tests cannot establish kernel or
firmware safety.

Upstream documents console validation of the helper lifecycle on firmware
12.02. Other SDK-supported firmware remains experimental. A title using this
option must qualify its exact helper, firmware, jailbreak and elfldr with
repeated launch, `/data` proof, normal use and clean-exit cycles. Never fall
back to a raw-pointer helper when Lapy rejects a target.

The equivalent integration was exercised for three consecutive launches on a
test console: each run reported the embedded `helper` path, verified `/data`,
reached the application UI, and left FTP and elfldr responsive. That is
functional evidence, not a long-term kernel-stability guarantee.

## Credits and licenses

Lapy was created by
[ArkSama / Team PHU](https://github.com/ArkSama/PS5-Lapy-JB-Daemon). The
cooperative exact-title helper used here is maintained in
[mpereiraesaa's fork](https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon).
Credit belongs to both projects and their contributors.

Lapy is MIT licensed; its published shared protocol header is
LGPL-2.1-or-later. The pinned `ps5log` build input is GPL-3.0-or-later. Their
source references and roles are recorded in `THIRD_PARTY_NOTICES.md`.
