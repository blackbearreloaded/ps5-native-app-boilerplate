# Elevated-capability C++ examples

These source-only examples show how a native application uses the caller-only
interface proposed in
[blackbearreloaded/kstuff-lite#1](https://github.com/blackbearreloaded/kstuff-lite/pull/1).
They are intentionally isolated from the boilerplate build, packaging, CI, and
application metadata.

Add the kstuff-lite repository's `include/` directory to the application's
include search path. The examples include `<kstuff.h>` and therefore do not
duplicate operation numbers, magic values, ABI versions, or syscall transport.

| Source | Demonstrated capability |
| --- | --- |
| [`self-elevation/src/main.cpp`](self-elevation/src/main.cpp) | Request profile 1, inspect the caller's authority, read a system file, validate a reversible `/data` lifecycle, and write/reopen/read/compare `/data/hello-from-sandbox.txt` |
| [`process-memory/src/main.cpp`](process-memory/src/main.cpp) | Request profile 2 and read, replace, verify, and restore one owned helper sentinel; use a bounded ptrace fallback when firmware denies `mdbg` writes |
| [`system-capabilities/src/main.cpp`](system-capabilities/src/main.cpp) | Request profile 1, mount/read/unmount a private nullfs view, open/close `/dev/mdctl`, and probe raw-socket availability without transmitting |
| [`ptrace/src/main.cpp`](ptrace/src/main.cpp) | Request profile 3 and use platform `ptrace` to attach, read, replace, verify, restore, and terminate only the owned helper |
| [`process-memory/helper/main.cpp`](process-memory/helper/main.cpp) | Publish an explicitly owned sentinel target and independently confirm that both memory probes restore it |

Every example keeps the elevated target bounded: kstuff operates only on its
calling process, while process-memory and ptrace operations target only the
supplied helper. Mutable values are restored before the ptrace-based probes
deterministically terminate their owned helper. Temporary mounts and files are
removed, privileged devices receive no command, and the raw socket sends no
traffic.

The suite has been exercised on firmware 6.02 and 12.70. Profile 1, nullfs,
privileged-device open/close, raw-socket creation, and the standalone bounded
ptrace example passed on both. Firmware 6.02 permits direct `mdbg` writes;
firmware 12.70 permits `mdbg` reads but returns `EPERM` for writes. The combined
`mdbg`-to-ptrace fallback is retained as an experimental example and was
compiled, but its final revision was not rerun on hardware. These are capability
demonstrations, not a recommendation that ordinary applications modify or trace
other processes.
