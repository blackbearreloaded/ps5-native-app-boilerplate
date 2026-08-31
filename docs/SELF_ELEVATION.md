# Self-elevation example

The optional `self-elevation` example validates a native application requesting
its own data-access profile from a compatible kstuff build. The default
boilerplate application remains sandboxed.

This is not a standalone exploit. The matching kstuff environment must already
be active before the application starts. The app neither packages a helper
payload nor connects to elfldr.

## Build

```sh
make self-elevation-ffpfsc
```

The command builds title `PPSA99792` from
`examples/self-elevation/src/main.cpp` and writes both the deployable directory
and `dist/PPSA99792.ffpfsc`.

## Request contract

The example enters through libkernel's syscall wrapper and kstuff's existing
`getppid` bridge. It does not contain a kernel address or firmware offset.

| Field | Value |
| --- | --- |
| Operation | `7` in the upper 32 bits of the syscall number |
| Syscall | `getppid` (`39`) in the lower 32 bits |
| Argument 1 | Magic `0x31564c4553355350` |
| Argument 2 | ABI version `1` |
| Argument 3 | Data-access profile `1` |

The same application calls bounded inspection operation `8`, selector `1`, to
read its own kernel credential authority ID before and after elevation. This
operation accepts no address and performs no kernel write.

The app-side integration is intentionally isolated in one function:

```cpp
[[nodiscard]] SyscallResult request_kstuff_self_elevation() noexcept
{
    return kstuff_request(self_elevation_operation, request_magic,
                          request_version, data_access_profile);
}
```

`request_kstuff_self_elevation()` expresses the application operation;
`kstuff_request()` contains the low-level bridge transport. The matching
kernel-side handler validates the request and elevates only the calling
process.

A zero return value means kstuff applied and reread the requested state.
Unknown magic, ABI versions, profiles, and firmware fail closed. With the PS5
libkernel wrapper, rejected requests return `-1` and set `errno`.

The corresponding kstuff implementation is tracked in
[blackbearreloaded/kstuff-lite#1](https://github.com/blackbearreloaded/kstuff-lite/pull/1).

## Acceptance test

The application verifies all of the following in one launch:

1. `/data` is inaccessible before elevation.
2. The bridge control succeeds, while invalid magic, version, and profile are
   rejected with `EINVAL` without changing sandbox access.
3. First and repeated valid requests both succeed.
4. UID, effective UID, and real GID become zero. The data-access profile does
   not rewrite the supplementary-group array, so `getegid()` may retain its
   prior value; this is recorded but is not an acceptance condition.
5. A global system library can be opened and read.
6. A reversible `/data` lifecycle succeeds: create directory, create file,
   write, chmod, stat, rename, read, verify, unlink, and remove directory.
7. The caller's kernel-resident authority ID matches the requested profile.
8. `/data/self-elevation-validation.txt` is written and read back.

The app then remains alive for normal shell-mediated closure. Do not call
`exit()` as a substitute for the title-aware close path.

## Hardware evidence

The original profile-1 path passed on firmware 6.02 and 12.70. The extended
firmware 6.02 run also confirmed the bounded authority read:

```text
sandbox_before=80020002 sandbox_after_rejections=80020002
first_elevation=ok:0 repeated_elevation=ok:0
credentials_before=1,1,1,1 credentials_after=0,0,0,1
kernel_auth_id_before=ok:4400001084c2052d after=ok:4801000000000013
global_read=0 path=/system/common/lib/libSceLibcInternal.sprx
filesystem_lifecycle=0 operations=mkdir,create,write,chmod,stat,rename,read,unlink,rmdir
```

Hardware validation covers firmware 6.02 and 12.70. The request ABI remains
firmware-neutral; kstuff owns firmware-specific layout selection. Other
whitelisted firmware revisions must not be described as hardware-tested until
validated on those consoles.

See [the complete capability suite](CAPABILITY_SUITE.md) for profiles 2 and 3,
the other bounded probes, build commands, run order, and exact acceptance
results.

## Scope

- Only the calling process can be modified; the API accepts no PID or kernel
  pointer.
- The example performs only a bounded read of its own kernel-resident authority
  ID; it exposes no kernel address.
- No console setting or update behavior is accessed.
- Use the smallest capability profile that serves the application. A regular
  sandboxed app remains the preferred default.
