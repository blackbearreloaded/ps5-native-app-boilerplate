/*
 * ps5-native-app-boilerplate - Elevation protocol and failure-path regression.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <algorithm>
#include <cassert>
#include <vector>

// Exercise the actual client and helper without a console or kernel writes.
#define main elevation_payload_main
#include "../examples/sandbox-elevation/payload/main.cpp"
#undef main
#include "../examples/sandbox-elevation/src/elevation.cpp"

namespace test
{
constexpr std::intptr_t base = static_cast<std::intptr_t>(UINT64_C(0xffff800000100000));
std::array<std::uint8_t, 1024> memory{};
int writes = 0;
int fail_write = 0;
bool fail_all_writes = false;
std::vector<std::uint8_t> replies;
std::vector<std::uint8_t> sent;
std::size_t received = 0;
bool helper_read = false;
int prepare_calls = 0;
int prepare_result = 0;
int closes = 0;

void reset_client(const Message &first, const Message &last)
{
    replies.resize(2 * sizeof(Message));
    std::memcpy(replies.data(), &first, sizeof(first));
    std::memcpy(replies.data() + sizeof(first), &last, sizeof(last));
    sent.clear();
    received = 0;
    helper_read = false;
    prepare_calls = prepare_result = closes = 0;
}
} // namespace test

extern "C"
{
    extern const std::intptr_t KERNEL_ADDRESS_ALLPROC = test::base;
    extern const off_t KERNEL_OFFSET_PROC_P_PID = 0xbc;
    extern const off_t KERNEL_OFFSET_PROC_P_UCRED = 0x40;
    extern const off_t KERNEL_OFFSET_PROC_P_FD = 0x48;
    extern const off_t KERNEL_OFFSET_UCRED_CR_UID = 4;
    extern const off_t KERNEL_OFFSET_UCRED_CR_SCEAUTHID = 0x58;
    extern const off_t KERNEL_OFFSET_UCRED_CR_SCECAPS = 0x60;
    extern const off_t KERNEL_OFFSET_UCRED_CR_SCEATTRS = 0x80;
    extern const off_t KERNEL_OFFSET_FILEDESC_FD_RDIR = 0x10;
    extern const off_t KERNEL_OFFSET_FILEDESC_FD_JDIR = 0x18;

    int kernel_copyout(std::intptr_t address, void *data, std::size_t size)
    {
        const auto offset = static_cast<std::size_t>(address - test::base);
        if (offset > test::memory.size() || size > test::memory.size() - offset)
            return -1;
        std::memcpy(data, test::memory.data() + offset, size);
        return 0;
    }
    int kernel_copyin(const void *data, std::intptr_t address, std::size_t size)
    {
        ++test::writes;
        if (test::fail_all_writes || test::writes == test::fail_write)
            return -1;
        const auto offset = static_cast<std::size_t>(address - test::base);
        assert(offset <= test::memory.size() && size <= test::memory.size() - offset);
        std::memcpy(test::memory.data() + offset, data, size);
        return 0;
    }
    std::intptr_t kernel_get_root_vnode()
    {
        return test::base + 900;
    }
    std::uint32_t kernel_get_fw_version()
    {
        return 0x06020004;
    }
    payload_args_t *payload_get_args()
    {
        return nullptr;
    }
    int sceKernelGetAppInfo(pid_t, AppInfo *)
    {
        return -1;
    }
    int klog_printf(const char *, ...)
    {
        return 0;
    }
    int sceKernelOpen(const char *, int, mode_t)
    {
        return 10;
    }
    int sceKernelClose(int)
    {
        ++test::closes;
        return 0;
    }
    std::int64_t sceKernelRead(int, void *buffer, std::size_t)
    {
        if (test::helper_read)
            return 0;
        test::helper_read = true;
        std::memcpy(buffer,
                    "\x7f"
                    "ELF",
                    4);
        return 4;
    }
    int sceNetSocket(const char *, int, int, int)
    {
        return 20;
    }
    int sceNetSocketClose(int)
    {
        ++test::closes;
        return 0;
    }
    int sceNetConnect(int, const void *, std::uint32_t)
    {
        return 0;
    }
    int sceNetSetsockopt(int, int, int, const void *, std::uint32_t)
    {
        return 0;
    }
    int sceNetSend(int, const void *bytes, std::size_t size, int)
    {
        const auto count = std::min(size, std::size_t{7});
        const auto *start = static_cast<const std::uint8_t *>(bytes);
        test::sent.insert(test::sent.end(), start, start + count);
        return static_cast<int>(count);
    }
    int sceNetRecv(int, void *bytes, std::size_t size, int)
    {
        const auto count = std::min({size, std::size_t{3}, test::replies.size() - test::received});
        std::memcpy(bytes, test::replies.data() + test::received, count);
        test::received += count;
        return static_cast<int>(count);
    }
    int seteuid(uid_t) noexcept
    {
        ++test::prepare_calls;
        return test::prepare_result;
    }
}

int main()
{
    Message request{};
    request.pid = 123;
    const std::array<std::uint8_t, 24> golden{'E', 'L', 'V', '1', 1,   0, 24, 0, 1, 0, 0, 0,
                                              1,   0,   0,   0,   123, 0, 0,  0, 0, 0, 0, 0};
    assert(std::memcmp(&request, golden.data(), golden.size()) == 0);
    assert(elevation::wire::validate(request) == Status::ok);
    auto invalid = request;
    invalid.magic = 0;
    assert(handle_request(invalid) == Status::invalid_request);
    invalid = request;
    invalid.version = 2;
    assert(handle_request(invalid) == Status::unsupported_version);
    invalid = request;
    invalid.size = 25;
    assert(handle_request(invalid) == Status::invalid_request);
    invalid = request;
    invalid.capability = static_cast<Capability>(2);
    assert(handle_request(invalid) == Status::unsupported_capability);
    invalid = request;
    invalid.pid = UINT32_MAX;
    assert(handle_request(invalid) == Status::invalid_request);
    invalid = request;
    invalid.kind = Kind::response;
    assert(handle_request(invalid) == Status::invalid_request);
    invalid = request;
    invalid.status = Status::apply_failed;
    assert(handle_request(invalid) == Status::invalid_request);
    assert(test::writes == 0);

    Message prepare{};
    prepare.pid = static_cast<std::uint32_t>(getpid());
    prepare.kind = Kind::prepare;
    auto response = prepare;
    response.kind = Kind::response;
    test::reset_client(prepare, response);
    assert(elevation::request(Capability::filesystem) == Status::ok);
    assert(test::prepare_calls == 1 && test::closes == 2);
    assert(test::sent.size() == 4 + 2 * sizeof(Message));
    Message prepared{};
    std::memcpy(&prepared, test::sent.data() + 4 + sizeof(Message), sizeof(Message));
    assert(elevation::wire::matches(prepared, prepare, Kind::prepared));

    test::reset_client(prepare, response);
    test::prepare_result = -1;
    assert(elevation::request(Capability::filesystem) == Status::prepare_failed);
    test::reset_client(prepare, response);
    test::replies.resize(sizeof(Message) - 1);
    assert(elevation::request(Capability::filesystem) == Status::transport_error);
    assert(test::prepare_calls == 0 && test::closes == 2);
    auto wrong_pid = prepare;
    ++wrong_pid.pid;
    test::reset_client(wrong_pid, response);
    assert(elevation::request(Capability::filesystem) == Status::protocol_error);
    response.status = Status::apply_failed;
    test::reset_client(prepare, response);
    assert(elevation::request(Capability::filesystem) == Status::apply_failed);
    assert(elevation::request(static_cast<Capability>(2)) == Status::unsupported_capability);

    const Target target{test::base, test::base + 128, test::base + 512};
    State original{};
    original.identity.fill(1000);
    original.authority = 1234;
    original.root = test::base + 800;
    original.jail = test::base + 850;
    assert(write_state(target, original));
    assert(grant_filesystem(target, original) == Status::ok);
    State state{};
    assert(read_state(target, state));
    assert(state.root == kernel_get_root_vnode() && state.identity[0] == 0);

    // Every individual kernel write can fail; the complete original state must return.
    for (int failure = 1; failure <= 6; ++failure)
    {
        test::fail_write = 0;
        assert(write_state(target, original));
        test::writes = 0;
        test::fail_write = failure;
        assert(grant_filesystem(target, original) == Status::apply_failed);
        assert(read_state(target, state) && state == original);
    }
    test::fail_all_writes = true;
    assert(grant_filesystem(target, original) == Status::rollback_failed);
}
