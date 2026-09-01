/*
 * ps5-native-app-boilerplate - Owned process-memory capability probe.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Reads and modifies one sentinel in an explicitly owned helper process. It
 * uses mdbg where supported and a controlled ptrace fallback when required.
 * The fallback restores the sentinel before terminating its owned helper.
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
constexpr char helper_result_path[] = "/data/g2-process-helper-result.txt";
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
constexpr std::uint64_t wait4_syscall = 7;
constexpr std::uint64_t ptrace_syscall = 26;
constexpr std::uint64_t ptrace_kill = 8;
constexpr std::uint64_t ptrace_attach = 10;
constexpr std::uint64_t ptrace_io = 12;
constexpr int ptrace_write_data = 2;
constexpr std::uint64_t wait_no_hang = 1;
constexpr std::uint64_t wait_untraced = 2;
constexpr unsigned int trace_wait_attempts = 200;
constexpr std::uint32_t trace_wait_interval_microseconds = 10000;

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

struct MdbgTransferResult
{
    std::uint64_t call_value;
    int call_error;
    bool call_failed;
    std::int32_t response_status;
    std::uint64_t transferred;
    std::uint64_t remaining;
};

static_assert(sizeof(HelperInfo) == 48);
static_assert(sizeof(PtraceIoDescriptor) == 32);
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
    trace_attach = 12,
    trace_wait = 13,
    trace_release = 14,
    trace_exit = 15,
    helper_completion = 16,
    receipt = 17,
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
                                 std::uint64_t argument1, std::uint64_t argument2,
                                 std::uint64_t argument3 = 0) noexcept
{
    int *const error_location = __error();
    *error_location = 0;
    constexpr std::uintptr_t libkernel_syscall_setup_offset = 7;
    const auto syscall_entry = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(&getpid) +
                                                        libkernel_syscall_setup_offset);
    register std::uint64_t syscall_argument3 asm("r10") = argument3;
    register std::uint64_t argument4 asm("r8") = 0;
    register std::uint64_t argument5 asm("r9") = 0;
    std::uint8_t failed = 0;
    asm volatile("call *%[entry]\n\tsetc %1"
                 : "+a"(number), "=qm"(failed), "+r"(syscall_argument3), "+r"(argument4),
                   "+r"(argument5)
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

MdbgTransferResult mdbg_transfer(std::uint64_t operation, std::int32_t pid,
                                 std::uint64_t remote_address, void *local_buffer,
                                 std::size_t length) noexcept
{
    MdbgCommand command{mdbg_command_type, operation};
    MdbgArguments arguments{pid, 0, remote_address, reinterpret_cast<std::uint64_t>(local_buffer),
                            length};
    MdbgTransferResult transfer{};
    transfer.remaining = length;

    for (unsigned int attempt = 0; attempt < 4; ++attempt)
    {
        MdbgResponse response{};
        const SyscallResult call =
            invoke_raw_syscall(mdbg_call_syscall, reinterpret_cast<std::uint64_t>(&command),
                               reinterpret_cast<std::uint64_t>(&arguments),
                               reinterpret_cast<std::uint64_t>(&response));
        transfer.call_value = call.value;
        transfer.call_error = call.error;
        transfer.call_failed = call.failed || call.value == UINT64_MAX;
        transfer.response_status = response.status;
        transfer.transferred += response.length;
        transfer.remaining = arguments.length;
        if (transfer.call_failed)
            return transfer;
        if (response.length > arguments.length)
        {
            transfer.call_error = -2;
            transfer.call_failed = true;
            return transfer;
        }
        arguments.source += response.length;
        arguments.destination += response.length;
        arguments.length -= response.length;
        transfer.remaining = arguments.length;
        if (arguments.length == 0)
            return transfer;
        if (response.status == 0 || response.length == 0)
        {
            transfer.call_error = -3;
            transfer.call_failed = true;
            return transfer;
        }
    }
    transfer.call_error = -4;
    transfer.call_failed = true;
    return transfer;
}

MdbgTransferResult read_marker(const HelperInfo &info, std::uint64_t &value) noexcept
{
    return mdbg_transfer(mdbg_read_operation, info.pid, info.address, &value, sizeof(value));
}

MdbgTransferResult write_marker(const HelperInfo &info, std::uint64_t value) noexcept
{
    return mdbg_transfer(mdbg_write_operation, info.pid, info.address, &value, sizeof(value));
}

[[nodiscard]] bool succeeded(const MdbgTransferResult &result) noexcept
{
    return !result.call_failed && result.call_value == 0 && result.remaining == 0;
}

[[nodiscard]] bool succeeded(const SyscallResult &result) noexcept
{
    return !result.failed && result.value != UINT64_MAX;
}

SyscallResult ptrace_request(std::uint64_t request, std::int32_t pid,
                             void *address = nullptr, std::uint64_t data = 0) noexcept
{
    return invoke_raw_syscall(ptrace_syscall, request, static_cast<std::uint64_t>(pid),
                              reinterpret_cast<std::uint64_t>(address), data);
}

bool wait_for_trace_stop(std::int32_t pid) noexcept
{
    for (unsigned int attempt = 0; attempt < trace_wait_attempts; ++attempt)
    {
        int wait_status = 0;
        const SyscallResult waited =
            invoke_raw_syscall(wait4_syscall, static_cast<std::uint64_t>(pid),
                               reinterpret_cast<std::uint64_t>(&wait_status),
                               wait_no_hang | wait_untraced, 0);
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

bool wait_for_trace_exit(std::int32_t pid) noexcept
{
    for (unsigned int attempt = 0; attempt < trace_wait_attempts; ++attempt)
    {
        int wait_status = 0;
        const SyscallResult waited =
            invoke_raw_syscall(wait4_syscall, static_cast<std::uint64_t>(pid),
                               reinterpret_cast<std::uint64_t>(&wait_status),
                               wait_no_hang | wait_untraced, 0);
        if (!succeeded(waited))
            return false;
        if (waited.value == static_cast<std::uint64_t>(pid))
            return (wait_status & 0x7f) != 0x7f;
        if (waited.value != 0)
            return false;
        (void)sceKernelUsleep(trace_wait_interval_microseconds);
    }
    return false;
}

bool wait_for_helper_completion(const HelperInfo &info) noexcept
{
    std::array<char, 160> expected{};
    const int expected_length = std::snprintf(
        expected.data(), expected.size(), "result=PASS pid=%d marker=%016llx\n", info.pid,
        static_cast<unsigned long long>(original_value));
    if (expected_length <= 0 || static_cast<std::size_t>(expected_length) >= expected.size())
        return false;

    for (unsigned int attempt = 0; attempt < trace_wait_attempts; ++attempt)
    {
        KernelFile input{sceKernelOpen(helper_result_path, open_read_only, 0)};
        if (input.valid())
        {
            std::array<char, 160> actual{};
            const std::int64_t length = sceKernelRead(input.get(), actual.data(), actual.size());
            if (length == expected_length)
            {
                bool matches = true;
                for (int index = 0; index < expected_length; ++index)
                    matches = matches && actual[static_cast<std::size_t>(index)] ==
                                             expected[static_cast<std::size_t>(index)];
                if (matches)
                    return true;
            }
        }
        (void)sceKernelUsleep(trace_wait_interval_microseconds);
    }
    return false;
}

int ptrace_write(const HelperInfo &info, std::uint64_t value) noexcept
{
    PtraceIoDescriptor descriptor{ptrace_write_data, 0,
                                  reinterpret_cast<void *>(info.address), &value, sizeof(value)};
    const SyscallResult result =
        invoke_raw_syscall(ptrace_syscall, ptrace_io, static_cast<std::uint64_t>(info.pid),
                           reinterpret_cast<std::uint64_t>(&descriptor), 0);
    return succeeded(result) ? 0 : result.error ? result.error : 5;
}

class TracePauseGuard
{
  public:
    TracePauseGuard(const HelperInfo &info, int &debug_profile_error, int &read_profile_error,
                    unsigned int &profile_switches, SyscallResult &attach_result,
                    SyscallResult &release_result) noexcept
        : info_{info}, debug_profile_error_{debug_profile_error},
          read_profile_error_{read_profile_error}, profile_switches_{profile_switches},
          attach_result_{attach_result}, release_result_{release_result}
    {
    }
    ~TracePauseGuard()
    {
        if (replacement_written_)
        {
            (void)request_profile(KSTUFF_PROFILE_DEBUG, debug_profile_error_);
            (void)ptrace_write(info_, original_value);
        }
        if (attached_)
            (void)release();
    }
    TracePauseGuard(const TracePauseGuard &) = delete;
    TracePauseGuard &operator=(const TracePauseGuard &) = delete;

    [[nodiscard]] bool pause() noexcept
    {
        if (!request_profile(KSTUFF_PROFILE_DEBUG, debug_profile_error_))
            return false;
        attach_result_ = ptrace_request(ptrace_attach, info_.pid);
        if (!succeeded(attach_result_))
            return false;
        attached_ = true;
        if (!wait_for_trace_stop(info_.pid))
            return false;
        return true;
    }

    [[nodiscard]] bool use_process_memory_profile() noexcept
    {
        return request_profile(KSTUFF_PROFILE_PROCESS_MEMORY, read_profile_error_);
    }

    [[nodiscard]] bool use_debug_profile() noexcept
    {
        return request_profile(KSTUFF_PROFILE_DEBUG, debug_profile_error_);
    }

    [[nodiscard]] bool release() noexcept
    {
        if (!attached_)
            return true;
        if (!use_debug_profile())
            return false;
        release_result_ = ptrace_request(ptrace_kill, info_.pid);
        if (!succeeded(release_result_))
            return false;
        attached_ = false;
        return true;
    }

    void replacement_written() noexcept
    {
        replacement_written_ = true;
    }
    void restored() noexcept
    {
        replacement_written_ = false;
    }

  private:
    [[nodiscard]] bool request_profile(kstuff_profile_t profile, int &result) noexcept
    {
        result = kstuff_request_profile(profile);
        ++profile_switches_;
        return result == 0;
    }

    const HelperInfo &info_;
    int &debug_profile_error_;
    int &read_profile_error_;
    unsigned int &profile_switches_;
    SyscallResult &attach_result_;
    SyscallResult &release_result_;
    bool attached_ = false;
    bool replacement_written_ = false;
};

Stage validate_process_memory(const HelperInfo &info, MdbgTransferResult &last_read,
                              MdbgTransferResult &last_write, int &debug_profile_error,
                              int &read_profile_error, unsigned int &profile_switches,
                              SyscallResult &attach_result, SyscallResult &release_result,
                              int &trace_exit_confirmed, bool &helper_completion_confirmed,
                              bool &ptrace_fallback_used, int &ptrace_write_error) noexcept
{
    std::uint64_t value = 0;
    last_read = read_marker(info, value);
    if (!succeeded(last_read) || value != original_value)
        return Stage::marker_read;

    TracePauseGuard trace{info, debug_profile_error, read_profile_error, profile_switches,
                          attach_result, release_result};
    last_write = write_marker(info, replacement_value);
    if (!succeeded(last_write))
    {
        if (last_write.call_error != 1)
            return Stage::marker_write;
        if (!trace.pause())
            return succeeded(attach_result) ? Stage::trace_wait : Stage::trace_attach;
        ptrace_fallback_used = true;
        ptrace_write_error = ptrace_write(info, replacement_value);
        if (ptrace_write_error != 0)
            return Stage::marker_write;
        if (!trace.use_process_memory_profile())
            return Stage::elevation;
    }
    trace.replacement_written();
    last_read = read_marker(info, value);
    if (!succeeded(last_read) || value != replacement_value)
        return Stage::replacement_verify;
    (void)sceKernelUsleep(500000);
    if (ptrace_fallback_used)
    {
        if (!trace.use_debug_profile())
            return Stage::elevation;
        ptrace_write_error = ptrace_write(info, original_value);
        if (ptrace_write_error != 0 || !trace.use_process_memory_profile())
            return Stage::marker_restore;
    }
    else
    {
        last_write = write_marker(info, original_value);
        if (!succeeded(last_write))
            return Stage::marker_restore;
    }
    last_read = read_marker(info, value);
    if (!succeeded(last_read) || value != original_value)
        return Stage::restoration_verify;
    trace.restored();
    if (!trace.release())
        return Stage::trace_release;
    if (ptrace_fallback_used)
    {
        trace_exit_confirmed = wait_for_trace_exit(info.pid) ? 1 : 0;
        if (trace_exit_confirmed == 0)
            return Stage::trace_exit;
        helper_completion_confirmed = true;
    }
    else
    {
        helper_completion_confirmed = wait_for_helper_completion(info);
        if (!helper_completion_confirmed)
            return Stage::helper_completion;
    }
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
    MdbgTransferResult last_read{};
    MdbgTransferResult last_write{};
    int debug_profile_error = -1;
    int read_profile_error = -1;
    unsigned int profile_switches = 0;
    SyscallResult attach_result{};
    SyscallResult release_result{};
    int trace_exit_confirmed = -1;
    bool helper_completion_confirmed = false;
    bool ptrace_fallback_used = false;
    int ptrace_write_error = -1;
    if (stage == Stage::pass)
        stage = validate_process_memory(info, last_read, last_write, debug_profile_error,
                                        read_profile_error, profile_switches, attach_result,
                                        release_result, trace_exit_confirmed,
                                        helper_completion_confirmed, ptrace_fallback_used,
                                        ptrace_write_error);

    std::array<char, 768> receipt{};
    const int receipt_length = std::snprintf(
        receipt.data(), receipt.size(),
        "result=%s stage=%d app_pid=%d helper_pid=%d\n"
        "sandbox_control=%08x probe_error=%d elevation_error=%d debug_profile_error=%d "
        "read_profile_error=%d profile_switches=%u helper_read=%d\n"
        "mdbg_read=value:%llu,failed:%d,error:%08x,status:%d,transferred:%llu,remaining:%llu\n"
        "mdbg_write=value:%llu,failed:%d,error:%08x,status:%d,transferred:%llu,remaining:%llu\n"
        "ptrace_fallback=%d ptrace_write_error=%08x "
        "trace_attach=value:%llu,failed:%d,error:%08x trace_release=value:%llu,failed:%d,error:%08x\n"
        "trace_exit_confirmed=%d helper_shutdown=%d mode=%s receipt=%s\n"
        "address=%016llx original=%016llx replacement=%016llx restored=%s\n",
        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage), own_pid, info.pid,
        static_cast<std::uint32_t>(sandbox_control), probe_error, elevation_error,
        debug_profile_error, read_profile_error, profile_switches, helper_read,
        static_cast<unsigned long long>(last_read.call_value), last_read.call_failed ? 1 : 0,
        static_cast<std::uint32_t>(last_read.call_error), last_read.response_status,
        static_cast<unsigned long long>(last_read.transferred),
        static_cast<unsigned long long>(last_read.remaining),
        static_cast<unsigned long long>(last_write.call_value), last_write.call_failed ? 1 : 0,
        static_cast<std::uint32_t>(last_write.call_error), last_write.response_status,
        static_cast<unsigned long long>(last_write.transferred),
        static_cast<unsigned long long>(last_write.remaining),
        ptrace_fallback_used ? 1 : 0, static_cast<std::uint32_t>(ptrace_write_error),
        static_cast<unsigned long long>(attach_result.value), attach_result.failed ? 1 : 0,
        static_cast<std::uint32_t>(attach_result.error),
        static_cast<unsigned long long>(release_result.value), release_result.failed ? 1 : 0,
        static_cast<std::uint32_t>(release_result.error),
        trace_exit_confirmed, helper_completion_confirmed ? 1 : 0,
        ptrace_fallback_used ? "trace-kill" : "normal-exit",
        ptrace_fallback_used ? "n/a" : helper_result_path,
        static_cast<unsigned long long>(info.address),
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
                        "%s: PROCESS MEMORY | owned helper read, write, restore, shutdown | stage=%d",
                        stage == Stage::pass ? "PASS" : "FAIL", static_cast<int>(stage));
    report(summary.data());
    stay_alive();
}
