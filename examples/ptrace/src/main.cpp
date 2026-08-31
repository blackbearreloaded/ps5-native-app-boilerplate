/*
 * ps5-native-app-boilerplate - Owned ptrace capability probe.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Attaches only to the explicitly launched test helper, replaces and restores
 * one sentinel while stopped, restores it, then terminates only that owned
 * helper through the tracing interface.
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
constexpr char receipt_path[] = "/data/g6-ptrace-result.txt";
constexpr std::uint64_t helper_magic = UINT64_C(0x325245504c454847);
constexpr std::uint32_t helper_version = 1;
constexpr std::uint64_t helper_cookie = UINT64_C(0x6f574e4544473241);
constexpr std::uint64_t original_value = UINT64_C(0x1122334455667788);
constexpr std::uint64_t replacement_value = UINT64_C(0xa55aa55a5aa55aa5);

constexpr std::uint64_t wait4_syscall = 7;
constexpr std::uint64_t ptrace_syscall = 26;
constexpr std::uint64_t wait_no_hang = 1;
constexpr unsigned int trace_wait_attempts = 200;
constexpr unsigned int trace_stop_event_limit = 4;
constexpr std::uint32_t trace_wait_interval_microseconds = 10000;
constexpr std::uint64_t ptrace_kill = 8;
constexpr std::uint64_t ptrace_attach = 10;
constexpr std::uint64_t ptrace_io = 12;
constexpr int ptrace_read_data = 1;
constexpr int ptrace_write_data = 2;

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

struct PtraceIoDescriptor
{
    int operation;
    std::uint32_t reserved;
    void *remote;
    void *local;
    std::size_t length;
};

static_assert(sizeof(HelperInfo) == 48);
static_assert(sizeof(PtraceIoDescriptor) == 32);

enum class Stage : int
{
    pass = 0,
    sandbox_control = 1,
    bridge = 2,
    elevation = 3,
    helper_read = 4,
    helper_validation = 5,
    attach = 6,
    wait = 7,
    marker_read = 8,
    marker_write = 9,
    replacement_verify = 10,
    marker_restore = 11,
    restoration_verify = 12,
    helper_kill = 13,
    helper_termination = 14,
    receipt = 15,
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
    return !result.failed;
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

SyscallResult ptrace_request(std::uint64_t request, std::int32_t pid, void *address = nullptr,
                             std::uint64_t data = 0) noexcept
{
    return invoke_raw_syscall(ptrace_syscall, request, static_cast<std::uint64_t>(pid),
                              reinterpret_cast<std::uint64_t>(address), data);
}

int ptrace_transfer(std::uint64_t request, const HelperInfo &info, std::uint64_t remote_address,
                    std::uint64_t &value) noexcept
{
    PtraceIoDescriptor descriptor{static_cast<int>(request), 0,
                                  reinterpret_cast<void *>(remote_address), &value, sizeof(value)};
    const SyscallResult result = ptrace_request(ptrace_io, info.pid, &descriptor, 0);
    return succeeded(result) ? 0 : static_cast<int>(result.value);
}

bool wait_for_trace_stop(std::int32_t pid) noexcept
{
    for (unsigned int attempt = 0; attempt < trace_wait_attempts; ++attempt)
    {
        int wait_status = 0;
        const SyscallResult waited =
            invoke_raw_syscall(wait4_syscall, static_cast<std::uint64_t>(pid),
                               reinterpret_cast<std::uint64_t>(&wait_status), wait_no_hang, 0);
        if (!succeeded(waited))
            return false;
        if (waited.value == static_cast<std::uint64_t>(pid))
            return (wait_status & 0x7f) == 0x7f;
        if (waited.value != 0)
            return false;
        (void)sceKernelUsleep(trace_wait_interval_microseconds);
    }
    return false;
}

bool wait_for_trace_termination(std::int32_t pid) noexcept
{
    unsigned int stop_events = 0;
    for (unsigned int attempt = 0; attempt < trace_wait_attempts; ++attempt)
    {
        int wait_status = 0;
        const SyscallResult waited =
            invoke_raw_syscall(wait4_syscall, static_cast<std::uint64_t>(pid),
                               reinterpret_cast<std::uint64_t>(&wait_status), wait_no_hang, 0);
        if (!succeeded(waited))
            return false;
        if (waited.value == static_cast<std::uint64_t>(pid))
        {
            if ((wait_status & 0x7f) == 0)
                return true;
            if ((wait_status & 0x7f) != 0x7f)
                return true;
            if ((wait_status & 0x7f) == 0x7f && stop_events++ < trace_stop_event_limit)
            {
                std::array<char, 96> message{};
                (void)std::snprintf(message.data(), message.size(),
                                    "[G6-PTRACE] continuing trace event status=%08x\n",
                                    static_cast<unsigned int>(wait_status));
                (void)sceKernelDebugOutText(0, message.data());
                if (!succeeded(ptrace_request(ptrace_kill, pid)))
                    return false;
                continue;
            }
            return false;
        }
        if (waited.value != 0)
            return false;
        (void)sceKernelUsleep(trace_wait_interval_microseconds);
    }
    return false;
}

class TraceGuard
{
  public:
    explicit TraceGuard(const HelperInfo &info) noexcept : info_{info}
    {
    }
    ~TraceGuard()
    {
        if (!attached_ && replacement_written_ &&
            succeeded(ptrace_request(ptrace_attach, info_.pid)))
        {
            attached_ = true;
            (void)wait_for_trace_stop(info_.pid);
        }
        if (replacement_written_)
        {
            std::uint64_t original = original_value;
            (void)ptrace_transfer(ptrace_write_data, info_, info_.address, original);
        }
        if (attached_)
            (void)ptrace_request(ptrace_kill, info_.pid);
    }
    TraceGuard(const TraceGuard &) = delete;
    TraceGuard &operator=(const TraceGuard &) = delete;

    void attached() noexcept
    {
        attached_ = true;
    }
    void replacement_written() noexcept
    {
        replacement_written_ = true;
    }
    void restored() noexcept
    {
        replacement_written_ = false;
    }
    void completed() noexcept
    {
        attached_ = false;
    }

  private:
    const HelperInfo &info_;
    bool attached_ = false;
    bool replacement_written_ = false;
};

Stage validate_ptrace(const HelperInfo &info) noexcept
{
    TraceGuard guard{info};
    (void)sceKernelDebugOutText(0, "[G6-PTRACE] attach begin\n");
    if (!succeeded(ptrace_request(ptrace_attach, info.pid)))
        return Stage::attach;
    guard.attached();
    (void)sceKernelDebugOutText(0, "[G6-PTRACE] attach returned; wait begin\n");

    if (!wait_for_trace_stop(info.pid))
        return Stage::wait;
    (void)sceKernelDebugOutText(0, "[G6-PTRACE] helper stopped\n");

    std::uint64_t value = 0;
    if (ptrace_transfer(ptrace_read_data, info, info.address, value) != 0 ||
        value != original_value)
        return Stage::marker_read;
    value = replacement_value;
    if (ptrace_transfer(ptrace_write_data, info, info.address, value) != 0)
        return Stage::marker_write;
    guard.replacement_written();
    value = 0;
    if (ptrace_transfer(ptrace_read_data, info, info.address, value) != 0 ||
        value != replacement_value)
        return Stage::replacement_verify;
    value = original_value;
    if (ptrace_transfer(ptrace_write_data, info, info.address, value) != 0)
        return Stage::marker_restore;
    value = 0;
    if (ptrace_transfer(ptrace_read_data, info, info.address, value) != 0 ||
        value != original_value)
        return Stage::restoration_verify;
    guard.restored();

    if (!succeeded(ptrace_request(ptrace_kill, info.pid)))
        return Stage::helper_kill;
    if (!wait_for_trace_termination(info.pid))
        return Stage::helper_termination;
    guard.completed();
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
    (void)std::snprintf(debug.data(), debug.size(), "[G6-PTRACE] %s\n", message);
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
        stage == Stage::pass ? kstuff_request_profile(KSTUFF_PROFILE_DEBUG) : -1;
    if (stage == Stage::pass && elevation_error != 0)
        stage = Stage::elevation;

    HelperInfo info{};
    const int helper_read = elevation_error == 0 ? read_helper_info(info) : -1;
    if (stage == Stage::pass && helper_read != 0)
        stage = Stage::helper_read;
    if (stage == Stage::pass && !valid_helper(info, own_pid))
        stage = Stage::helper_validation;
    if (stage == Stage::pass)
        stage = validate_ptrace(info);

    const int stage_value = static_cast<int>(stage);
    const bool restored =
        stage == Stage::pass || stage_value >= static_cast<int>(Stage::helper_kill);
    const bool kill_requested =
        stage == Stage::pass || stage_value >= static_cast<int>(Stage::helper_termination);
    std::array<char, 640> receipt{};
    const int receipt_length =
        std::snprintf(receipt.data(), receipt.size(),
                      "result=%s stage=%d app_pid=%d helper_pid=%d\n"
                      "sandbox_control=%08x probe_error=%d elevation_error=%d helper_read=%d\n"
                      "address=%016llx original=%016llx replacement=%016llx restored=%s\n"
                      "helper_kill_requested=%s helper_termination_confirmed=%s\n",
                      stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage), own_pid,
                      info.pid, static_cast<std::uint32_t>(sandbox_control), probe_error,
                      elevation_error, helper_read, static_cast<unsigned long long>(info.address),
                      static_cast<unsigned long long>(info.original),
                      static_cast<unsigned long long>(info.replacement),
                      restored ? "yes" : "best-effort", kill_requested ? "yes" : "no",
                      stage == Stage::pass ? "yes" : "no");
    if (elevation_error == 0 && receipt_length > 0 &&
        static_cast<std::size_t>(receipt_length) < receipt.size() &&
        write_receipt(receipt.data(), static_cast<std::size_t>(receipt_length)) != 0 &&
        stage == Stage::pass)
        stage = Stage::receipt;

    std::array<char, 192> summary{};
    (void)std::snprintf(summary.data(), summary.size(),
                        "%s: DEBUGGING | owned ptrace read, write, restore, terminate | stage=%d",
                        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage));
    report(summary.data());
    stay_alive();
}
