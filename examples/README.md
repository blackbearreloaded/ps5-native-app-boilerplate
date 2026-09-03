# Minimal self-elevation example

[`self-elevation/src/main.cpp`](self-elevation/src/main.cpp) shows the complete application-side flow for the caller-only interface proposed in [blackbearreloaded/kstuff-lite#1](https://github.com/blackbearreloaded/kstuff-lite/pull/1). It requests the data-access profile, writes `/data/hello-from-sandbox.txt`, closes and reopens the file, and verifies that it contains `hello from the sandboxed app`.

Add kstuff-lite's `include/` directory to the application include path, then include `<kstuff.h>`. The elevation-specific code is only:

```cpp
int request_data_access()
{
    if (const int error = kstuff_probe(); error != 0)
        return error;
    return kstuff_request_profile(KSTUFF_PROFILE_DATA_ACCESS);
}
```

`kstuff_probe()` verifies that a compatible request bridge is active. `kstuff_request_profile()` applies the named profile to the calling process and returns zero on success or a positive `errno` value on failure. The request affects only that process and lasts until it exits.

The example contains no raw syscall numbers, request operation numbers, ABI magic values, authority IDs, or firmware offsets. Those protocol details belong to kstuff-lite and are encapsulated by `<kstuff.h>`. `O_WRONLY`, `O_CREAT`, `O_TRUNC`, and `O_RDONLY` are standard file-open flags from `<fcntl.h>`; `0666` is the conventional file permission mode, not a kstuff value.

The source intentionally demonstrates one ordinary application use case. The earlier process-memory, ptrace, mount, raw-socket, and privileged-device files were hardware-validation probes, not dependencies of self-elevation, and are deliberately excluded from this developer-facing example.
