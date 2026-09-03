# Sandbox elevation proof

The default boilerplate remains a normal sandboxed application. This optional
example proves a narrow capability transition for an app whose owner has
already started a compatible kernel-payload environment and elfldr.

## What it does

`PPSA99790` first attempts to create `/data/hello-from-sandbox.txt`. The
sandboxed attempt must fail.
It then reads `/app0/sandbox-elevator.elf`, streams it to elfldr through
`127.0.0.1:9021`, and closes the socket to signal the end of the payload.

The helper searches for exactly `PPSA99790`, changes that process's credentials
and root/jail vnode pointers, verifies every changed field, and exits. The same
app process then creates, reopens, reads, and byte-verifies the named canary.
Its expected contents are:

```text
hello from the sandboxed app
pid=<PID> before_open=80020002 write_read=verified
```

Closing the app destroys its elevated process state. The canary deliberately
remains for independent retrieval and must be deleted after the app closes.

## Build

From Linux or WSL:

```bash
make sandbox-elevation-ffpfsc
```

The output is `dist/PPSA99790.ffpfsc`. The target downloads the same pinned
native dependencies as the normal build, builds the exact-title helper,
packages it in `/app0`, and produces the compressed image. Generated helper
binaries stay under ignored `build/` and `dist/` directories.

## Requirements and limits

- A compatible kstuff/kernel-payload environment must already be active.
- elfldr must already listen on TCP port 9021.
- The supplied helper recognizes only title `PPSA99790`.
- The proof is hardware-validated on firmware 6.02. Other firmware and payload
  combinations require their own validation.
- This is not a standalone exploit and does not change console settings.
- Do not generalize the helper into an arbitrary process-elevation service.

The helper and application source are independently authored and distributed
under GPL-3.0-or-later.
