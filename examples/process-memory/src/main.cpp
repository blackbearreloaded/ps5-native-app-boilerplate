/*
 * ps5-native-app-boilerplate - Owned process-memory capability probe.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Uses the versioned kstuff process-memory profile to replace and restore one
 * sentinel in an explicitly owned helper process.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <kstuff.h>

namespace
{
constexpr int open_read_only = 0;
constexpr int open_write_create_truncate = 0x0601;
constexpr std::uint16_t file_mode_0666 = 0x01b6;

constexpr char helper_info_path[] = "/data/g2-process-helper.bin";
constexpr char receipt_path[] = "/data/g2-process-memory-result.txt";
constexpr std::uint64_t helper_magic = UINT64_C(0x325245504c454847);
constexpr std::uint32_t helper_version = 1;
constexpr std::uint64_t helper_cookie = UINT64_C(0x6f574e4544473241);
constexpr std::uint64_t original_value = UINT64_C(0x1122334455667788);
constexpr std::uint64_t replacement_value = UINT64_C(0xa55aa55a5aa55aa5);

constexpr std::uint64_t mdbg_call_syscall = 573;
constexpr std::uint64_t mdbg_command_type = 1;
constexpr std::uint64_t mdbg_read_operation = 0x12;
constexpr std::uint64_t mdbg_write_operation = 0x13;

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

struct HelperInfo
{
    std::uint64_t magic;
    std::uint32_t version;
    std::int32_t pid;
    std::uint64_t address;
    std::uint64_t original;
    std::uint64_t replacement;
    std::uint64_t cookie;
};

struct MdbgCommand
{
    std::uint64_t type;
    std::uint64_t operation;
};

struct MdbgArguments
{
    std::int32_t pid;
    std::uint32_t reserved;
    std::uint64_t source;
    std::uint64_t destination;
    std::uint64_t length;
};

struct MdbgResponse
{
    std::int32_t status;
    std::uint32_t reserved;
    std::uint64_t length;
};

static_assert(sizeof(HelperInfo) == 48);
static_assert(sizeof(MdbgArguments) == 32);
static_assert(sizeof(MdbgResponse) == 16);

enum class Stage : int
{
    pass = 0,
    sandbox_control = 1,
    bridge = 2,
    elevation = 3,
    helper_read = 4,
    helper_validation = 5,
    marker_read = 6,
    marker_write = 7,
    replacement_verify = 8,
    marker_restore = 9,
    restoration_verify = 10,
    receipt = 11,
};

extern "C"
{
    int *__error();
    int getpid();
    int sceKernelClose(int descriptor);
    int sceKernelDebugOutText(int channel, const char *text);
    int sceKernelOpen(const char *path, int flags, std::uint16_t mode);
    std::int64_t sceKernelRead(int descriptor, void *buffer, std::size_t length);
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

SyscallResult invoke_raw_syscall(std::uint64_t number, std::uint64_t argument0,
                                 std::uint64_t argument1, std::uint64_t argument2) noexcept
{
    int *const error_location = __error();
    *error_location = 0;
    constexpr std::uintptr_t libkernel_syscall_entry_offset = 7;
    const auto syscall_entry = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(&getpid) +
                                                        libkernel_syscall_entry_offset);
    register std::uint64_t argument3 asm("r10") = 0;
    register std::uint64_t argument4 asm("r8") = 0;
    register std::uint64_t argument5 asm("r9") = 0;
    std::uint8_t failed = 0;
    asm volatile("call *%[entry]\n\tsetc %1"
                 : "+a"(number), "=qm"(failed), "+r"(argument3), "+r"(argument4), "+r"(argument5)
                 : [entry] "r"(syscall_entry), "D"(argument0), "S"(argument1), "d"(argument2)
                 : "rcx", "r11", "memory");
    return {number, failed != 0, *error_location};
}

int read_helper_info(HelperInfo &info) noexcept
{
    KernelFile input{sceKernelOpen(helper_info_path, open_read_only, 0)};
    if (!input.valid())
        return 1;
    if (sceKernelRead(input.get(), &info, sizeof(info)) != static_cast<std::int64_t>(sizeof(info)))
        return 2;
    std::uint8_t extra = 0;
    return sceKernelRead(input.get(), &extra, sizeof(extra)) == 0 ? 0 : 3;
}

[[nodiscard]] bool valid_helper(const HelperInfo &info, int own_pid) noexcept
{
    return info.magic == helper_magic && info.version == helper_version && info.pid > 1 &&
           info.pid != own_pid && info.address != 0 && (info.address >> 48) == 0 &&
           (info.address % alignof(std::uint64_t)) == 0 && info.original == original_value &&
           info.replacement == replacement_value && info.cookie == helper_cookie;
}

int mdbg_transfer(std::uint64_t operation, std::int32_t pid, std::uint64_t remote_address,
                  void *local_buffer, std::size_t length) noexcept
{
    MdbgCommand command{mdbg_command_type, operation};
    MdbgArguments arguments{pid, 0, remote_address, reinterpret_cast<std::uint64_t>(local_buffer),
                            length};

    for (unsigned int attempt = 0; attempt < 4; ++attempt)
    {
        MdbgResponse response{};
        const SyscallResult result =
            invoke_raw_syscall(mdbg_call_syscall, reinterpret_cast<std::uint64_t>(&command),
                               reinterpret_cast<std::uint64_t>(&arguments),
                               reinterpret_cast<std::uint64_t>(&response));
        if (result.failed)
            return 1000 + static_cast<int>(result.value);
        if (response.length > arguments.length)
            return 2;
        arguments.source += response.length;
        arguments.destination += response.length;
        arguments.length -= response.length;
        if (arguments.length == 0)
            return 0;
        if (response.status == 0 || response.length == 0)
            return 3;
    }
    return 4;
}

int read_marker(const HelperInfo &info, std::uint64_t &value) noexcept
{
    return mdbg_transfer(mdbg_read_operation, info.pid, info.address, &value, sizeof(value));
}

int write_marker(const HelperInfo &info, std::uint64_t value) noexcept
{
    return mdbg_transfer(mdbg_write_operation, info.pid, info.address, &value, sizeof(value));
}

class MarkerRestore
{
  public:
    explicit MarkerRestore(const HelperInfo &info) noexcept : info_{info}
    {
    }
    ~MarkerRestore()
    {
        if (armed_)
            (void)write_marker(info_, original_value);
    }
    MarkerRestore(const MarkerRestore &) = delete;
    MarkerRestore &operator=(const MarkerRestore &) = delete;

    void arm() noexcept
    {
        armed_ = true;
    }
    void disarm() noexcept
    {
        armed_ = false;
    }

  private:
    const HelperInfo &info_;
    bool armed_ = false;
};

Stage validate_process_memory(const HelperInfo &info) noexcept
{
    std::uint64_t value = 0;
    if (read_marker(info, value) != 0 || value != original_value)
        return Stage::marker_read;

    MarkerRestore restore{info};
    if (write_marker(info, replacement_value) != 0)
        return Stage::marker_write;
    restore.arm();
    if (read_marker(info, value) != 0 || value != replacement_value)
        return Stage::replacement_verify;
    (void)sceKernelUsleep(500000);
    if (write_marker(info, original_value) != 0)
        return Stage::marker_restore;
    if (read_marker(info, value) != 0 || value != original_value)
        return Stage::restoration_verify;
    restore.disarm();
    return Stage::pass;
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
    (void)std::snprintf(debug.data(), debug.size(), "[G2-PROCESS-MEMORY] %s\n", message);
    (void)sceKernelDebugOutText(0, debug.data());
    (void)std::snprintf(notification.message, sizeof(notification.message), "%s", message);
    (void)sceKernelSendNotificationRequest(0, &notification, sizeof(notification), 0);
}
} // namespace

int main()
{
    const int own_pid = getpid();
    Stage stage = Stage::pass;
    const int sandbox_control = sceKernelOpen(helper_info_path, open_read_only, 0);
    if (sandbox_control >= 0)
    {
        (void)sceKernelClose(sandbox_control);
        stage = Stage::sandbox_control;
    }

    const int probe_error = kstuff_probe();
    if (stage == Stage::pass && probe_error != 0)
        stage = Stage::bridge;
    const int elevation_error =
        stage == Stage::pass ? kstuff_request_profile(KSTUFF_PROFILE_PROCESS_MEMORY) : -1;
    if (stage == Stage::pass && elevation_error != 0)
        stage = Stage::elevation;

    HelperInfo info{};
    const int helper_read = elevation_error == 0 ? read_helper_info(info) : -1;
    if (stage == Stage::pass && helper_read != 0)
        stage = Stage::helper_read;
    if (stage == Stage::pass && !valid_helper(info, own_pid))
        stage = Stage::helper_validation;
    if (stage == Stage::pass)
        stage = validate_process_memory(info);

    std::array<char, 640> receipt{};
    const int receipt_length =
        std::snprintf(receipt.data(), receipt.size(),
                      "result=%s stage=%d app_pid=%d helper_pid=%d\n"
                      "sandbox_control=%08x probe_error=%d elevation_error=%d helper_read=%d\n"
                      "address=%016llx original=%016llx replacement=%016llx restored=%s\n",
                      stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage), own_pid,
                      info.pid, static_cast<std::uint32_t>(sandbox_control), probe_error,
                      elevation_error, helper_read, static_cast<unsigned long long>(info.address),
                      static_cast<unsigned long long>(info.original),
                      static_cast<unsigned long long>(info.replacement),
                      stage == Stage::pass ? "yes" : "unknown");
    if (elevation_error == 0 && receipt_length > 0 &&
        static_cast<std::size_t>(receipt_length) < receipt.size() &&
        write_receipt(receipt.data(), static_cast<std::size_t>(receipt_length)) != 0 &&
        stage == Stage::pass)
        stage = Stage::receipt;

    std::array<char, 192> summary{};
    (void)std::snprintf(summary.data(), summary.size(),
                        "%s: PROCESS MEMORY | owned helper read, write, restore | stage=%d",
                        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage));
    report(summary.data());
    stay_alive();
}
