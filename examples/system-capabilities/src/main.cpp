/*
 * ps5-native-app-boilerplate - Reversible elevated system capability probes.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Mounts and verifies a dedicated nullfs view, opens and closes the memory-disk
 * control device without issuing commands, and creates a raw ICMP socket
 * without transmitting any traffic.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <kstuff.h>

namespace
{
constexpr int open_read_only = 0;
constexpr int open_read_write = 2;
constexpr int open_write_create_truncate = 0x0601;
constexpr std::uint16_t file_mode_0666 = 0x01b6;
constexpr std::uint16_t file_mode_0777 = 0x01ff;

constexpr char receipt_path[] = "/data/g3-g5-system-capabilities-result.txt";
constexpr char mount_source_path[] = "/data/g3-nullfs-source";
constexpr char mount_target_path[] = "/data/g3-nullfs-target";
constexpr char source_marker_path[] = "/data/g3-nullfs-source/marker.txt";
constexpr char target_marker_path[] = "/data/g3-nullfs-target/marker.txt";
constexpr char marker_text[] = "kstuff nullfs capability probe\n";
constexpr char option_fstype[] = "fstype";
constexpr char option_from[] = "from";
constexpr char option_fspath[] = "fspath";
constexpr char nullfs_name[] = "nullfs";
constexpr char privileged_device_path[] = "/dev/mdctl";

constexpr std::uint64_t nmount_syscall = 378;
constexpr std::uint64_t unmount_syscall = 22;
constexpr std::uint64_t socket_syscall = 97;
constexpr int forced_unmount = 0x00080000;
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
    int source_directory;
    int target_directory;
    int source_write;
    int target_read;
    int marker_matches;
    int cleanup_error;
};

struct IoVector
{
    void *base;
    std::size_t length;
};

enum class Stage : int
{
    pass = 0,
    bridge = 1,
    elevation = 2,
    mount = 3,
    privileged_device = 4,
    raw_socket = 5,
    receipt = 6,
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

[[nodiscard]] bool succeeded(const SyscallResult &result) noexcept
{
    return !result.failed && result.value != UINT64_MAX;
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

template <std::size_t Size> IoVector string_option(const char (&text)[Size]) noexcept
{
    return {const_cast<char *>(text), Size};
}

int write_marker() noexcept
{
    KernelFile output{
        sceKernelOpen(source_marker_path, open_write_create_truncate, file_mode_0666)};
    if (!output.valid())
        return output.get();
    return sceKernelWrite(output.get(), marker_text, sizeof(marker_text) - 1) ==
                   static_cast<std::int64_t>(sizeof(marker_text) - 1)
               ? 0
               : -1;
}

int read_mounted_marker(bool &matches) noexcept
{
    std::array<char, sizeof(marker_text)> data{};
    KernelFile input{sceKernelOpen(target_marker_path, open_read_only, 0)};
    if (!input.valid())
        return input.get();
    const auto length = sceKernelRead(input.get(), data.data(), data.size());
    matches = length == static_cast<std::int64_t>(sizeof(marker_text) - 1) &&
              std::memcmp(data.data(), marker_text, sizeof(marker_text) - 1) == 0;
    return static_cast<int>(length);
}

int remove_probe_paths() noexcept
{
    int error = 0;
    (void)sceKernelUnlink(source_marker_path);
    if (sceKernelRmdir(mount_target_path) != 0)
        error |= 1;
    if (sceKernelRmdir(mount_source_path) != 0)
        error |= 2;
    return error;
}

MountProbeResult probe_mount() noexcept
{
    (void)invoke_raw_syscall(unmount_syscall, reinterpret_cast<std::uint64_t>(mount_target_path),
                             forced_unmount);
    (void)remove_probe_paths();

    MountProbeResult result{{UINT64_MAX, true, 0}, {UINT64_MAX, true, 0}, -1, -1, -1, -1, 0, -1};
    result.source_directory = sceKernelMkdir(mount_source_path, file_mode_0777);
    result.target_directory = sceKernelMkdir(mount_target_path, file_mode_0777);
    if (result.source_directory != 0 || result.target_directory != 0)
    {
        result.cleanup_error = remove_probe_paths();
        return result;
    }

    result.source_write = write_marker();
    if (result.source_write != 0)
    {
        result.cleanup_error = remove_probe_paths();
        return result;
    }

    std::array<IoVector, 6> options{
        string_option(option_fstype), string_option(nullfs_name),
        string_option(option_from),   string_option(mount_source_path),
        string_option(option_fspath), string_option(mount_target_path),
    };
    result.mounted =
        invoke_raw_syscall(nmount_syscall, reinterpret_cast<std::uint64_t>(options.data()),
                           static_cast<std::uint64_t>(options.size()), 0);
    if (!succeeded(result.mounted))
    {
        result.cleanup_error = remove_probe_paths();
        return result;
    }

    bool marker_matches = false;
    result.target_read = read_mounted_marker(marker_matches);
    result.marker_matches = marker_matches ? 1 : 0;

    result.unmounted =
        invoke_raw_syscall(unmount_syscall, reinterpret_cast<std::uint64_t>(mount_target_path), 0);
    if (!succeeded(result.unmounted))
        result.unmounted = invoke_raw_syscall(
            unmount_syscall, reinterpret_cast<std::uint64_t>(mount_target_path), forced_unmount);
    result.cleanup_error = succeeded(result.unmounted) ? remove_probe_paths() : -1;
    return result;
}

[[nodiscard]] bool mount_succeeded(const MountProbeResult &result) noexcept
{
    return succeeded(result.mounted) &&
           result.target_read == static_cast<int>(sizeof(marker_text) - 1) &&
           result.marker_matches == 1 && succeeded(result.unmounted) && result.cleanup_error == 0;
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

    const int probe_error = kstuff_probe();
    if (probe_error != 0)
        stage = Stage::bridge;
    const int elevation_error =
        stage == Stage::pass ? kstuff_request_profile(KSTUFF_PROFILE_DATA_ACCESS) : -1;
    if (stage == Stage::pass && elevation_error != 0)
        stage = Stage::elevation;

    MountProbeResult mount{};
    int device_after = -1;
    SyscallResult socket_after{0, true, 0};
    if (elevation_error == 0)
    {
        mount = probe_mount();
        if (!mount_succeeded(mount) && stage == Stage::pass)
            stage = Stage::mount;

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
        "probe_error=%d elevation_error=%d\n"
        "g3_mount=%d errno=%d unmount=%d errno=%d mkdir_source=%d mkdir_target=%d "
        "source_write=%d target_read=%d marker_matches=%d cleanup=%d source=%s target=%s "
        "type=%s\n"
        "g4_device_before=%08x after=%08x path=%s action=open-close-only\n"
        "g5_raw_socket_before=%s:%llu after=%s:%llu family=AF_INET type=SOCK_RAW "
        "protocol=ICMP transmitted=no\n",
        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage), pid, probe_error,
        elevation_error,
        succeeded(mount.mounted) ? 0 : -1, mount.mounted.error, succeeded(mount.unmounted) ? 0 : -1,
        mount.unmounted.error, mount.source_directory, mount.target_directory, mount.source_write,
        mount.target_read, mount.marker_matches, mount.cleanup_error, mount_source_path,
        mount_target_path, nullfs_name, static_cast<std::uint32_t>(device_before),
        static_cast<std::uint32_t>(device_after), privileged_device_path,
        socket_before.failed ? "err" : "ok", static_cast<unsigned long long>(socket_before.value),
        socket_after.failed ? "err" : "ok", static_cast<unsigned long long>(socket_after.value));
    if (elevation_error == 0 && receipt_length > 0 &&
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
