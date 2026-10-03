/*
 * ps5-native-app-boilerplate - Elevation client protocol regression.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

// Exercise the actual client without a console. The owned-reference backend
// has separate host tests because it cannot be modeled as raw vnode writes.
#include "../examples/sandbox-elevation/src/elevation.cpp"

using elevation::Capability;
using elevation::Status;
using elevation::wire::Kind;
using elevation::wire::Message;

namespace test
{
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
    int sceNetConnect(int, const void *address, std::uint32_t length)
    {
        assert(length == sizeof(NetSockaddrIn));
        const auto &endpoint = *static_cast<const NetSockaddrIn *>(address);
        assert(endpoint.length == length && endpoint.family == 2);
        assert(endpoint.address == 0x0100007f && endpoint.port == 0x3d23);
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
        const auto available = test::replies.size() - test::received;
        const auto count = std::min({size, std::size_t{3}, available});
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
    assert(elevation::wire::validate(invalid) == Status::invalid_request);
    invalid = request;
    invalid.version = 2;
    assert(elevation::wire::validate(invalid) == Status::unsupported_version);
    invalid = request;
    invalid.size = 25;
    assert(elevation::wire::validate(invalid) == Status::invalid_request);
    invalid = request;
    invalid.capability = static_cast<Capability>(2);
    assert(elevation::wire::validate(invalid) == Status::unsupported_capability);
    invalid = request;
    invalid.pid = UINT32_MAX;
    assert(elevation::wire::validate(invalid) == Status::invalid_request);

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
    assert(test::prepare_calls == 0 && test::closes == 2);

    for (int field = 0; field < 7; ++field)
    {
        auto bad = prepare;
        switch (field)
        {
        case 0:
            bad.magic = 0;
            break;
        case 1:
            bad.version = 2;
            break;
        case 2:
            bad.size = 25;
            break;
        case 3:
            bad.kind = static_cast<Kind>(99);
            break;
        case 4:
            bad.capability = static_cast<Capability>(2);
            break;
        case 5:
            bad.status = static_cast<Status>(99);
            break;
        case 6:
            bad.kind = Kind::response;
            break;
        }
        test::reset_client(bad, response);
        assert(elevation::request(Capability::filesystem) == Status::protocol_error);
        assert(test::prepare_calls == 0 && test::closes == 2);
    }

    auto wrong_response = response;
    ++wrong_response.pid;
    test::reset_client(prepare, wrong_response);
    assert(elevation::request(Capability::filesystem) == Status::protocol_error);
    assert(test::prepare_calls == 1 && test::closes == 2);
    test::reset_client(prepare, response);
    test::replies.resize(2 * sizeof(Message) - 1);
    assert(elevation::request(Capability::filesystem) == Status::transport_error);
    assert(test::prepare_calls == 1 && test::closes == 2);
    auto rejected = response;
    rejected.status = Status::target_mismatch;
    test::reset_client(rejected, response);
    assert(elevation::request(Capability::filesystem) == Status::target_mismatch);
    assert(test::prepare_calls == 0 && test::closes == 2);
    assert(elevation::request(Capability::filesystem, nullptr) == Status::invalid_request);
    response.status = Status::apply_failed;
    test::reset_client(prepare, response);
    assert(elevation::request(Capability::filesystem) == Status::apply_failed);
    assert(elevation::request(static_cast<Capability>(2)) == Status::unsupported_capability);
}
