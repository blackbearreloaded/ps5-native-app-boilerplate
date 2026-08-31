/*
 * ps5-native-app-boilerplate - Direct self-elevation validation.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Validates the versioned kstuff request contract, repeated elevation,
 * credential changes, a bounded kernel credential read, a reversible
 * filesystem lifecycle under /data, and read-only device-node checks.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace
{
constexpr int open_read_only = 0x0000;
constexpr int open_write_create_truncate = 0x0601;
constexpr std::uint16_t file_mode_0640 = 0x01a0;
constexpr std::uint16_t file_mode_0666 = 0x01b6;
constexpr std::uint16_t file_mode_0777 = 0x01ff;

constexpr char receipt_path[] = "/data/self-elevation-validation.txt";
constexpr char working_directory[] = "/data/self-elevation-validation";
constexpr char temporary_path[] = "/data/self-elevation-validation/stage.tmp";
constexpr char renamed_path[] = "/data/self-elevation-validation/stage.dat";
constexpr char lifecycle_payload[] = "self-elevation filesystem lifecycle\n";
constexpr char system_library_path[] = "/system/common/lib/libSceLibcInternal.sprx";
constexpr char kernel_memory_path[] = "/dev/kmem";
constexpr char physical_memory_path[] = "/dev/mem";

constexpr std::uint32_t getppid_syscall = 0x27;
constexpr std::uint32_t bridge_check_operation = UINT32_C(0xffffffff);
constexpr std::uint32_t self_elevation_operation = 7;
constexpr std::uint32_t self_inspection_operation = 8;
constexpr std::uint64_t request_magic = UINT64_C(0x31564c4553355350);
constexpr std::uint64_t request_version = 1;
constexpr std::uint64_t data_access_profile = 1;
constexpr std::uint64_t auth_id_selector = 1;
constexpr std::uint64_t system_auth_id = UINT64_C(0x4801000000000013);
constexpr std::uint64_t invalid_argument_error = 22;

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

struct Credentials
{
    int uid;
    int effective_uid;
    int gid;
    int effective_gid;
};

enum class Stage : int
{
    pass = 0,
    bridge = 2,
    invalid_magic = 3,
    invalid_version = 4,
    invalid_profile = 5,
    post_rejection_sandbox_control = 6,
    first_elevation = 7,
    repeated_elevation = 8,
    credentials = 9,
    global_read = 10,
    filesystem_lifecycle = 11,
    receipt = 12,
    kernel_inspection_before = 13,
    kernel_inspection_after = 14,
};

extern "C"
{
    int *__error();
    int getegid();
    int geteuid();
    int getgid();
    int getpid();
    int getuid();
    int sceKernelChmod(const char *path, std::uint16_t mode);
    int sceKernelClose(int descriptor);
    int sceKernelDebugOutText(int channel, const char *text);
    int sceKernelMkdir(const char *path, std::uint16_t mode);
    int sceKernelOpen(const char *path, int flags, std::uint16_t mode);
    std::int64_t sceKernelRead(int descriptor, void *buffer, std::size_t length);
    int sceKernelRename(const char *source, const char *destination);
    int sceKernelRmdir(const char *path);
    int sceKernelSendNotificationRequest(std::uint32_t device, void *request, std::size_t size,
                                         int blocking);
    int sceKernelStat(const char *path, void *status);
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

SyscallResult kstuff_request(std::uint32_t operation, std::uint64_t argument0,
                             std::uint64_t argument1, std::uint64_t argument2) noexcept
{
    int *const error_location = __error();
    *error_location = 0;
    constexpr std::uintptr_t libkernel_syscall_entry_offset = 7;
    const auto syscall_entry = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(&getpid) +
                                                        libkernel_syscall_entry_offset);
    std::uint64_t value = (static_cast<std::uint64_t>(operation) << 32) | getppid_syscall;
    register std::uint64_t argument3 asm("r10") = 0;
    register std::uint64_t argument4 asm("r8") = 0;
    register std::uint64_t argument5 asm("r9") = 0;
    std::uint8_t failed = 0;
    asm volatile("call *%[entry]\n\tsetc %1"
                 : "+a"(value), "=qm"(failed), "+r"(argument3), "+r"(argument4), "+r"(argument5)
                 : [entry] "r"(syscall_entry), "D"(argument0), "S"(argument1), "d"(argument2)
                 : "rcx", "r11", "memory");
    return {value, failed != 0, *error_location};
}

[[nodiscard]] SyscallResult request_kstuff_self_elevation() noexcept
{
    return kstuff_request(self_elevation_operation, request_magic, request_version,
                          data_access_profile);
}

void report(const char *message) noexcept
{
    std::array<char, 320> debug_message{};
    (void)std::snprintf(debug_message.data(), debug_message.size(), "[SELF-ELEVATION] %s\n",
                        message);
    (void)sceKernelDebugOutText(0, debug_message.data());
    (void)std::snprintf(notification.message, sizeof(notification.message), "%s", message);
    (void)sceKernelSendNotificationRequest(0, &notification, sizeof(notification), 0);
}

void report_controls(const SyscallResult &bridge, const SyscallResult &invalid_magic,
                     const SyscallResult &invalid_version, const SyscallResult &invalid_profile,
                     int sandbox_control) noexcept
{
    std::array<char, 320> message{};
    (void)std::snprintf(message.data(), message.size(),
                        "[SELF-ELEVATION] controls bridge=%u:%llx:%d magic=%u:%llx:%d "
                        "version=%u:%llx:%d profile=%u:%llx:%d sandbox=%08x\n",
                        bridge.failed, static_cast<unsigned long long>(bridge.value), bridge.error,
                        invalid_magic.failed, static_cast<unsigned long long>(invalid_magic.value),
                        invalid_magic.error, invalid_version.failed,
                        static_cast<unsigned long long>(invalid_version.value),
                        invalid_version.error, invalid_profile.failed,
                        static_cast<unsigned long long>(invalid_profile.value),
                        invalid_profile.error, static_cast<std::uint32_t>(sandbox_control));
    (void)sceKernelDebugOutText(0, message.data());
}

void report_checkpoint(const char *name, const SyscallResult &result) noexcept
{
    std::array<char, 192> message{};
    (void)std::snprintf(message.data(), message.size(),
                        "[SELF-ELEVATION] %s carry=%u value=%llx errno=%d\n", name, result.failed,
                        static_cast<unsigned long long>(result.value), result.error);
    (void)sceKernelDebugOutText(0, message.data());
}

void report_checkpoint(const char *name) noexcept
{
    std::array<char, 128> message{};
    (void)std::snprintf(message.data(), message.size(), "[SELF-ELEVATION] %s\n", name);
    (void)sceKernelDebugOutText(0, message.data());
}

[[nodiscard]] bool succeeded(const SyscallResult &result) noexcept
{
    return !result.failed && result.value == 0;
}

[[nodiscard]] bool inspected(const SyscallResult &result) noexcept
{
    return !result.failed && result.value != 0;
}

[[nodiscard]] bool rejected_as_invalid(const SyscallResult &result) noexcept
{
    return (result.failed && result.value == invalid_argument_error) ||
           (result.value == UINT64_MAX && result.error == invalid_argument_error);
}

[[nodiscard]] Credentials read_credentials() noexcept
{
    return {getuid(), geteuid(), getgid(), getegid()};
}

[[nodiscard]] bool has_root_identity(const Credentials &credentials) noexcept
{
    return credentials.uid == 0 && credentials.effective_uid == 0 && credentials.gid == 0;
}

[[nodiscard]] bool buffers_equal(const char *left, const char *right, std::size_t length) noexcept
{
    for (std::size_t index = 0; index < length; ++index)
    {
        if (left[index] != right[index])
            return false;
    }
    return true;
}

void remove_lifecycle_residue() noexcept
{
    (void)sceKernelUnlink(temporary_path);
    (void)sceKernelUnlink(renamed_path);
    (void)sceKernelRmdir(working_directory);
}

int validate_filesystem_lifecycle() noexcept
{
    remove_lifecycle_residue();
    if (sceKernelMkdir(working_directory, file_mode_0777) != 0)
        return 1;

    const auto cleanup = []() noexcept { remove_lifecycle_residue(); };
    {
        KernelFile output{
            sceKernelOpen(temporary_path, open_write_create_truncate, file_mode_0666)};
        if (!output.valid())
        {
            cleanup();
            return 2;
        }
        constexpr std::size_t payload_size = sizeof(lifecycle_payload) - 1;
        if (sceKernelWrite(output.get(), lifecycle_payload, payload_size) !=
            static_cast<std::int64_t>(payload_size))
        {
            cleanup();
            return 3;
        }
    }

    if (sceKernelChmod(temporary_path, file_mode_0640) != 0)
    {
        cleanup();
        return 4;
    }
    std::array<std::byte, 256> status{};
    if (sceKernelStat(temporary_path, status.data()) != 0)
    {
        cleanup();
        return 5;
    }
    if (sceKernelRename(temporary_path, renamed_path) != 0)
    {
        cleanup();
        return 6;
    }

    std::array<char, sizeof(lifecycle_payload) - 1> actual{};
    {
        KernelFile input{sceKernelOpen(renamed_path, open_read_only, 0)};
        if (!input.valid())
        {
            cleanup();
            return 7;
        }
        if (sceKernelRead(input.get(), actual.data(), actual.size()) !=
            static_cast<std::int64_t>(actual.size()))
        {
            cleanup();
            return 8;
        }
    }
    if (!buffers_equal(actual.data(), lifecycle_payload, actual.size()))
    {
        cleanup();
        return 9;
    }
    if (sceKernelUnlink(renamed_path) != 0)
    {
        cleanup();
        return 10;
    }
    if (sceKernelRmdir(working_directory) != 0)
        return 11;
    return 0;
}

int validate_global_read() noexcept
{
    KernelFile input{sceKernelOpen(system_library_path, open_read_only, 0)};
    if (!input.valid())
        return 1;
    std::array<std::uint8_t, 4> prefix{};
    if (sceKernelRead(input.get(), prefix.data(), prefix.size()) !=
        static_cast<std::int64_t>(prefix.size()))
        return 2;
    return (prefix[0] | prefix[1] | prefix[2] | prefix[3]) != 0 ? 0 : 3;
}

int probe_read_only_open(const char *path) noexcept
{
    KernelFile input{sceKernelOpen(path, open_read_only, 0)};
    return input.valid() ? 0 : input.get();
}

int write_and_verify_receipt(const char *text, std::size_t length) noexcept
{
    (void)sceKernelUnlink(receipt_path);
    {
        KernelFile output{sceKernelOpen(receipt_path, open_write_create_truncate, file_mode_0666)};
        if (!output.valid())
            return 1;
        if (sceKernelWrite(output.get(), text, length) != static_cast<std::int64_t>(length))
            return 2;
    }

    std::array<char, 1024> actual{};
    if (length > actual.size())
        return 3;
    {
        KernelFile input{sceKernelOpen(receipt_path, open_read_only, 0)};
        if (!input.valid())
            return 4;
        if (sceKernelRead(input.get(), actual.data(), length) != static_cast<std::int64_t>(length))
            return 5;
    }
    return buffers_equal(actual.data(), text, length) ? 0 : 6;
}
} // namespace

int main()
{
    const int pid = getpid();
    const Credentials before = read_credentials();
    const int kernel_memory_before = probe_read_only_open(kernel_memory_path);
    const int physical_memory_before = probe_read_only_open(physical_memory_path);
    Stage stage = Stage::pass;

    int sandbox_control = sceKernelOpen(receipt_path, open_write_create_truncate, file_mode_0666);
    if (sandbox_control >= 0)
    {
        (void)sceKernelClose(sandbox_control);
        (void)sceKernelUnlink(receipt_path);
        report("SELF ELEVATION CONTROL INVALID: /data was already writable");
        stay_alive();
    }

    const SyscallResult bridge =
        kstuff_request(bridge_check_operation, request_magic, request_version, data_access_profile);
    const SyscallResult invalid_magic = kstuff_request(self_elevation_operation, request_magic ^ 1,
                                                       request_version, data_access_profile);
    const SyscallResult invalid_version = kstuff_request(self_elevation_operation, request_magic,
                                                         request_version + 1, data_access_profile);
    const SyscallResult invalid_profile =
        kstuff_request(self_elevation_operation, request_magic, request_version, 0);
    const SyscallResult kernel_inspection_before =
        kstuff_request(self_inspection_operation, request_magic, request_version, auth_id_selector);

    if (!succeeded(bridge))
        stage = Stage::bridge;
    else if (!rejected_as_invalid(invalid_magic))
        stage = Stage::invalid_magic;
    else if (!rejected_as_invalid(invalid_version))
        stage = Stage::invalid_version;
    else if (!rejected_as_invalid(invalid_profile))
        stage = Stage::invalid_profile;
    else if (!inspected(kernel_inspection_before))
        stage = Stage::kernel_inspection_before;

    const int post_rejection_control =
        sceKernelOpen(receipt_path, open_write_create_truncate, file_mode_0666);
    if (post_rejection_control >= 0)
    {
        (void)sceKernelClose(post_rejection_control);
        (void)sceKernelUnlink(receipt_path);
        stage = Stage::post_rejection_sandbox_control;
    }
    report_controls(bridge, invalid_magic, invalid_version, invalid_profile,
                    post_rejection_control);

    SyscallResult first_elevation{0, true, 0};
    SyscallResult repeated_elevation{0, true, 0};
    Credentials after{};
    int global_read_result = -1;
    int filesystem_result = -1;
    int kernel_memory_after = -1;
    int physical_memory_after = -1;
    SyscallResult kernel_inspection_after{0, true, 0};
    if (succeeded(bridge) && post_rejection_control < 0)
    {
        report_checkpoint("first elevation begin");
        first_elevation = request_kstuff_self_elevation();
        report_checkpoint("first elevation end", first_elevation);
        if (!succeeded(first_elevation))
            stage = Stage::first_elevation;
    }
    if (succeeded(first_elevation))
    {
        report_checkpoint("repeated elevation begin");
        repeated_elevation = request_kstuff_self_elevation();
        report_checkpoint("repeated elevation end", repeated_elevation);
        if (!succeeded(repeated_elevation) && stage == Stage::pass)
            stage = Stage::repeated_elevation;
        report_checkpoint("credentials begin");
        after = read_credentials();
        report_checkpoint("credentials end");
        if (!has_root_identity(after) && stage == Stage::pass)
            stage = Stage::credentials;
        report_checkpoint("kernel inspection begin");
        kernel_inspection_after = kstuff_request(self_inspection_operation, request_magic,
                                                 request_version, auth_id_selector);
        report_checkpoint("kernel inspection end", kernel_inspection_after);
        if ((!inspected(kernel_inspection_after) ||
             kernel_inspection_after.value != system_auth_id) &&
            stage == Stage::pass)
            stage = Stage::kernel_inspection_after;
        report_checkpoint("global read begin");
        global_read_result = validate_global_read();
        report_checkpoint("global read end");
        if (global_read_result != 0 && stage == Stage::pass)
            stage = Stage::global_read;
        report_checkpoint("filesystem begin");
        filesystem_result = validate_filesystem_lifecycle();
        report_checkpoint("filesystem end");
        if (filesystem_result != 0 && stage == Stage::pass)
            stage = Stage::filesystem_lifecycle;
        report_checkpoint("kernel-memory device probes begin");
        kernel_memory_after = probe_read_only_open(kernel_memory_path);
        physical_memory_after = probe_read_only_open(physical_memory_path);
        report_checkpoint("kernel-memory device probes end");
    }

    std::array<char, 1024> receipt{};
    const int receipt_length = std::snprintf(
        receipt.data(), receipt.size(),
        "hello from the self-elevating sandbox app\n"
        "result=%s stage=%d pid=%d\n"
        "sandbox_before=%08x sandbox_after_rejections=%08x\n"
        "bridge=%s:%llu invalid_magic=%s:%llu invalid_version=%s:%llu invalid_profile=%s:%llu\n"
        "first_elevation=%s:%llu repeated_elevation=%s:%llu\n"
        "credentials_before=%d,%d,%d,%d credentials_after=%d,%d,%d,%d\n"
        "kernel_auth_id_before=%s:%016llx after=%s:%016llx expected=%016llx\n"
        "global_read=%d path=%s\n"
        "filesystem_lifecycle=%d "
        "operations=mkdir,create,write,chmod,stat,rename,read,unlink,rmdir\n"
        "kernel_memory_open_before=%08x,%08x after=%08x,%08x paths=%s,%s\n",
        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage), pid,
        static_cast<std::uint32_t>(sandbox_control),
        static_cast<std::uint32_t>(post_rejection_control), bridge.failed ? "err" : "ok",
        static_cast<unsigned long long>(bridge.value), invalid_magic.failed ? "err" : "ok",
        static_cast<unsigned long long>(invalid_magic.value), invalid_version.failed ? "err" : "ok",
        static_cast<unsigned long long>(invalid_version.value),
        invalid_profile.failed ? "err" : "ok",
        static_cast<unsigned long long>(invalid_profile.value),
        first_elevation.failed ? "err" : "ok",
        static_cast<unsigned long long>(first_elevation.value),
        repeated_elevation.failed ? "err" : "ok",
        static_cast<unsigned long long>(repeated_elevation.value), before.uid, before.effective_uid,
        before.gid, before.effective_gid, after.uid, after.effective_uid, after.gid,
        after.effective_gid, kernel_inspection_before.failed ? "err" : "ok",
        static_cast<unsigned long long>(kernel_inspection_before.value),
        kernel_inspection_after.failed ? "err" : "ok",
        static_cast<unsigned long long>(kernel_inspection_after.value),
        static_cast<unsigned long long>(system_auth_id), global_read_result, system_library_path,
        filesystem_result, static_cast<std::uint32_t>(kernel_memory_before),
        static_cast<std::uint32_t>(physical_memory_before),
        static_cast<std::uint32_t>(kernel_memory_after),
        static_cast<std::uint32_t>(physical_memory_after), kernel_memory_path,
        physical_memory_path);

    int receipt_result = -1;
    if (succeeded(first_elevation) && receipt_length > 0 &&
        static_cast<std::size_t>(receipt_length) < receipt.size())
    {
        receipt_result =
            write_and_verify_receipt(receipt.data(), static_cast<std::size_t>(receipt_length));
        if (receipt_result != 0 && stage == Stage::pass)
            stage = Stage::receipt;
    }

    std::array<char, 256> summary{};
    (void)std::snprintf(summary.data(), summary.size(),
                        "%s: DATA ACCESS | identity, system read, /data lifecycle | stage=%d",
                        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage));
    report(summary.data());
    stay_alive();
}
