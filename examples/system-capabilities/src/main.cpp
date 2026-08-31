/*
 * ps5-native-app-boilerplate - Reversible elevated system capability probes.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Mounts and unmounts procfs at a dedicated path, opens and closes the memory
 * disk control device without issuing commands, and creates a raw ICMP socket
 * without transmitting any traffic.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace
{
constexpr int open_read_only = 0;
constexpr int open_read_write = 2;
constexpr int open_write_create_truncate = 0x0601;
constexpr std::uint16_t file_mode_0666 = 0x01b6;
constexpr std::uint16_t file_mode_0777 = 0x01ff;

constexpr char receipt_path[] = "/data/g3-g5-system-capabilities-result.txt";
constexpr char mount_path[] = "/data/g3-procfs-mount";
constexpr char proc_status_path[] = "/data/g3-procfs-mount/curproc/status";
constexpr char procfs_name[] = "procfs";
constexpr char privileged_device_path[] = "/dev/mdctl";

constexpr std::uint64_t getppid_syscall = 39;
constexpr std::uint64_t mount_syscall = 21;
constexpr std::uint64_t unmount_syscall = 22;
constexpr std::uint64_t socket_syscall = 97;
constexpr std::uint64_t forced_unmount = UINT64_C(0x00080000);
constexpr std::uint32_t bridge_check_operation = UINT32_C(0xffffffff);
constexpr std::uint32_t self_elevation_operation = 7;
constexpr std::uint64_t request_magic = UINT64_C(0x31564c4553355350);
constexpr std::uint64_t request_version = 1;
constexpr std::uint64_t data_access_profile = 1;
constexpr std::uint64_t address_family_inet = 2;
constexpr std::uint64_t socket_type_raw = 3;
constexpr std::uint64_t protocol_icmp = 1;

struct NotificationRequest
{
    std::uint8_t reserved[45];
    char message[3075];
};

struct SyscallResult
{
    std::uint64_t value;
    bool failed;
    int error;
};

struct MountProbeResult
{
    SyscallResult mounted;
    SyscallResult unmounted;
    int directory;
    int status_read;
    int cleanup;
};

enum class Stage : int
{
    pass = 0,
    bridge = 1,
    elevation = 2,
    mount = 3,
    mount_cleanup = 4,
    privileged_device = 5,
    raw_socket = 6,
    receipt = 7,
};

extern "C"
{
    int *__error();
    int getpid();
    int sceKernelClose(int descriptor);
    int sceKernelDebugOutText(int channel, const char *text);
    int sceKernelMkdir(const char *path, std::uint16_t mode);
    int sceKernelOpen(const char *path, int flags, std::uint16_t mode);
    std::int64_t sceKernelRead(int descriptor, void *buffer, std::size_t length);
    int sceKernelRmdir(const char *path);
    int sceKernelSendNotificationRequest(std::uint32_t device, void *request, std::size_t size,
                                         int blocking);
    int sceKernelUnlink(const char *path);
    int sceKernelUsleep(std::uint32_t microseconds);
    std::int64_t sceKernelWrite(int descriptor, const void *buffer, std::size_t length);
}

class KernelFile
{
  public:
    explicit KernelFile(int descriptor) noexcept : descriptor_{descriptor}
    {
    }
    ~KernelFile()
    {
        if (descriptor_ >= 0)
            (void)sceKernelClose(descriptor_);
    }
    KernelFile(const KernelFile &) = delete;
    KernelFile &operator=(const KernelFile &) = delete;

    [[nodiscard]] int get() const noexcept
    {
        return descriptor_;
    }
    [[nodiscard]] bool valid() const noexcept
    {
        return descriptor_ >= 0;
    }

  private:
    int descriptor_;
};

NotificationRequest notification{};

[[noreturn]] void stay_alive() noexcept
{
    for (;;)
        (void)sceKernelUsleep(1000000);
}

SyscallResult invoke_raw_syscall(std::uint64_t number, std::uint64_t argument0 = 0,
                                 std::uint64_t argument1 = 0, std::uint64_t argument2 = 0,
                                 std::uint64_t argument3_value = 0,
                                 std::uint64_t argument4_value = 0,
                                 std::uint64_t argument5_value = 0) noexcept
{
    int *const error_location = __error();
    *error_location = 0;
    constexpr std::uintptr_t libkernel_syscall_entry_offset = 7;
    const auto syscall_entry = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(&getpid) +
                                                        libkernel_syscall_entry_offset);
    register std::uint64_t argument3 asm("r10") = argument3_value;
    register std::uint64_t argument4 asm("r8") = argument4_value;
    register std::uint64_t argument5 asm("r9") = argument5_value;
    std::uint8_t failed = 0;
    asm volatile("call *%[entry]\n\tsetc %1"
                 : "+a"(number), "=qm"(failed), "+r"(argument3), "+r"(argument4), "+r"(argument5)
                 : [entry] "r"(syscall_entry), "D"(argument0), "S"(argument1), "d"(argument2)
                 : "rcx", "r11", "memory");
    return {number, failed != 0, *error_location};
}

SyscallResult kstuff_request(std::uint32_t operation, std::uint64_t argument0,
                             std::uint64_t argument1, std::uint64_t argument2) noexcept
{
    return invoke_raw_syscall((static_cast<std::uint64_t>(operation) << 32) | getppid_syscall,
                              argument0, argument1, argument2);
}

[[nodiscard]] bool succeeded(const SyscallResult &result) noexcept
{
    return !result.failed;
}

[[nodiscard]] bool kstuff_succeeded(const SyscallResult &result) noexcept
{
    return succeeded(result) && result.value == 0;
}

int open_device() noexcept
{
    KernelFile device{sceKernelOpen(privileged_device_path, open_read_write, 0)};
    return device.get();
}

SyscallResult open_raw_socket() noexcept
{
    const SyscallResult result =
        invoke_raw_syscall(socket_syscall, address_family_inet, socket_type_raw, protocol_icmp);
    if (succeeded(result))
        (void)sceKernelClose(static_cast<int>(result.value));
    return result;
}

SyscallResult unmount_probe_path(std::uint64_t flags) noexcept
{
    return invoke_raw_syscall(unmount_syscall, reinterpret_cast<std::uint64_t>(mount_path), flags);
}

MountProbeResult probe_mount() noexcept
{
    (void)unmount_probe_path(forced_unmount);
    (void)sceKernelRmdir(mount_path);

    MountProbeResult result{{0, true, 0}, {0, true, 0}, -1, -1, -1};
    result.directory = sceKernelMkdir(mount_path, file_mode_0777);
    if (result.directory != 0)
        return result;

    result.mounted = invoke_raw_syscall(mount_syscall, reinterpret_cast<std::uint64_t>(procfs_name),
                                        reinterpret_cast<std::uint64_t>(mount_path), 0, 0);
    if (!succeeded(result.mounted))
    {
        result.cleanup = sceKernelRmdir(mount_path);
        return result;
    }

    {
        std::array<char, 1> byte{};
        KernelFile status{sceKernelOpen(proc_status_path, open_read_only, 0)};
        result.status_read =
            status.valid() ? static_cast<int>(sceKernelRead(status.get(), byte.data(), byte.size()))
                           : status.get();
    }

    result.unmounted = unmount_probe_path(0);
    if (!succeeded(result.unmounted))
        result.unmounted = unmount_probe_path(forced_unmount);
    if (succeeded(result.unmounted))
        result.cleanup = sceKernelRmdir(mount_path);
    else
        result.cleanup = -1;
    return result;
}

int write_receipt(const char *text, std::size_t length) noexcept
{
    (void)sceKernelUnlink(receipt_path);
    KernelFile output{sceKernelOpen(receipt_path, open_write_create_truncate, file_mode_0666)};
    if (!output.valid())
        return 1;
    return sceKernelWrite(output.get(), text, length) == static_cast<std::int64_t>(length) ? 0 : 2;
}

void report(const char *message) noexcept
{
    std::array<char, 320> debug{};
    (void)std::snprintf(debug.data(), debug.size(), "[G3-G5-SYSTEM] %s\n", message);
    (void)sceKernelDebugOutText(0, debug.data());
    (void)std::snprintf(notification.message, sizeof(notification.message), "%s", message);
    (void)sceKernelSendNotificationRequest(0, &notification, sizeof(notification), 0);
}
} // namespace

int main()
{
    const int pid = getpid();
    const int device_before = open_device();
    const SyscallResult socket_before = open_raw_socket();
    Stage stage = Stage::pass;

    const SyscallResult bridge =
        kstuff_request(bridge_check_operation, request_magic, request_version, data_access_profile);
    if (!kstuff_succeeded(bridge))
        stage = Stage::bridge;
    const SyscallResult elevation = stage == Stage::pass
                                        ? kstuff_request(self_elevation_operation, request_magic,
                                                         request_version, data_access_profile)
                                        : SyscallResult{0, true, 0};
    if (stage == Stage::pass && !kstuff_succeeded(elevation))
        stage = Stage::elevation;

    MountProbeResult mount{};
    int device_after = -1;
    SyscallResult socket_after{0, true, 0};
    if (kstuff_succeeded(elevation))
    {
        mount = probe_mount();
        if ((!succeeded(mount.mounted) || !succeeded(mount.unmounted)) && stage == Stage::pass)
            stage = Stage::mount;
        else if (mount.cleanup != 0 && stage == Stage::pass)
            stage = Stage::mount_cleanup;

        device_after = open_device();
        if (device_after < 0 && stage == Stage::pass)
            stage = Stage::privileged_device;

        socket_after = open_raw_socket();
        if (!succeeded(socket_after) && stage == Stage::pass)
            stage = Stage::raw_socket;
    }

    std::array<char, 1024> receipt{};
    const int receipt_length = std::snprintf(
        receipt.data(), receipt.size(),
        "result=%s stage=%d pid=%d\n"
        "bridge=%s:%llu elevation=%s:%llu\n"
        "g3_mount=%s:%llu unmount=%s:%llu mkdir=%d proc_read=%d cleanup=%d "
        "path=%s type=%s\n"
        "g4_device_before=%08x after=%08x path=%s action=open-close-only\n"
        "g5_raw_socket_before=%s:%llu after=%s:%llu family=AF_INET type=SOCK_RAW "
        "protocol=ICMP transmitted=no\n",
        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage), pid,
        bridge.failed ? "err" : "ok", static_cast<unsigned long long>(bridge.value),
        elevation.failed ? "err" : "ok", static_cast<unsigned long long>(elevation.value),
        mount.mounted.failed ? "err" : "ok", static_cast<unsigned long long>(mount.mounted.value),
        mount.unmounted.failed ? "err" : "ok",
        static_cast<unsigned long long>(mount.unmounted.value), mount.directory, mount.status_read,
        mount.cleanup, mount_path, procfs_name, static_cast<std::uint32_t>(device_before),
        static_cast<std::uint32_t>(device_after), privileged_device_path,
        socket_before.failed ? "err" : "ok", static_cast<unsigned long long>(socket_before.value),
        socket_after.failed ? "err" : "ok", static_cast<unsigned long long>(socket_after.value));
    if (kstuff_succeeded(elevation) && receipt_length > 0 &&
        static_cast<std::size_t>(receipt_length) < receipt.size() &&
        write_receipt(receipt.data(), static_cast<std::size_t>(receipt_length)) != 0 &&
        stage == Stage::pass)
        stage = Stage::receipt;

    std::array<char, 256> summary{};
    (void)std::snprintf(summary.data(), summary.size(),
                        "%s: SYSTEM ACCESS | mount, device, raw socket probe | stage=%d",
                        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage));
    report(summary.data());
    stay_alive();
}
