/*
 * ps5-native-app-boilerplate - Automated sandbox elevation proof.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Proves that /data is denied before elevation, submits the bundled exact-title
 * helper to loopback elfldr, then writes, reads, and verifies one named canary.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace
{
constexpr int open_read_only = 0x0000;
constexpr int open_write_create_truncate = 0x0601;
constexpr std::uint16_t file_mode_0666 = 0x01b6;
constexpr char canary_path[] = "/data/hello-from-sandbox.txt";
constexpr char helper_path[] = "/app0/sandbox-elevator.elf";
constexpr std::uint16_t elfldr_port = 9021;

struct NotificationRequest
{
    std::uint8_t reserved[45];
    char message[3075];
};

struct NetSockaddrIn
{
    std::uint8_t length;
    std::uint8_t family;
    std::uint16_t port;
    std::uint32_t address;
    std::uint16_t virtual_port;
    std::uint8_t zero[6];
};

extern "C"
{
    int getpid();
    int sceKernelClose(int descriptor);
    int sceKernelOpen(const char *path, int flags, std::uint16_t mode);
    std::int64_t sceKernelRead(int descriptor, void *buffer, std::size_t length);
    int sceKernelSendNotificationRequest(std::uint32_t device, void *request, std::size_t size,
                                         int blocking);
    int sceKernelUnlink(const char *path);
    int sceKernelUsleep(std::uint32_t microseconds);
    std::int64_t sceKernelWrite(int descriptor, const void *buffer, std::size_t length);
    int sceNetConnect(int socket, const void *address, std::uint32_t address_length);
    int sceNetSend(int socket, const void *data, std::size_t length, int flags);
    int sceNetSocket(const char *name, int domain, int type, int protocol);
    int sceNetSocketClose(int socket);
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

class Socket
{
  public:
    explicit Socket(int descriptor) noexcept : descriptor_{descriptor}
    {
    }
    ~Socket()
    {
        if (descriptor_ >= 0)
            (void)sceNetSocketClose(descriptor_);
    }

    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

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
int before_open_result = 0;

constexpr std::uint16_t big_endian(std::uint16_t value) noexcept
{
    return static_cast<std::uint16_t>((value << 8) | (value >> 8));
}

constexpr std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                             std::uint8_t d) noexcept
{
    return static_cast<std::uint32_t>(a) | (static_cast<std::uint32_t>(b) << 8) |
           (static_cast<std::uint32_t>(c) << 16) | (static_cast<std::uint32_t>(d) << 24);
}

void report(const char *message) noexcept
{
    (void)std::snprintf(notification.message, sizeof(notification.message), "%s", message);
    (void)sceKernelSendNotificationRequest(0, &notification, sizeof(notification), 0);
}

int send_all(int socket, const std::uint8_t *data, std::size_t length) noexcept
{
    std::size_t sent = 0;
    while (sent < length)
    {
        const int result = sceNetSend(socket, data + sent, length - sent, 0);
        if (result <= 0)
            return -1;
        sent += static_cast<std::size_t>(result);
    }
    return 0;
}

int submit_helper() noexcept
{
    KernelFile helper{sceKernelOpen(helper_path, open_read_only, 0)};
    if (!helper.valid())
        return -10;

    Socket socket{sceNetSocket("sandbox_elevator", 2, 1, 6)};
    if (!socket.valid())
        return -11;

    const NetSockaddrIn address{sizeof(address),    2, big_endian(elfldr_port),
                                ipv4(127, 0, 0, 1), 0, {0}};
    if (sceNetConnect(socket.get(), &address, sizeof(address)) < 0)
        return -12;

    std::array<std::uint8_t, 4096> buffer{};
    for (;;)
    {
        const std::int64_t count = sceKernelRead(helper.get(), buffer.data(), buffer.size());
        if (count == 0)
            return 0;
        if (count < 0 ||
            send_all(socket.get(), buffer.data(), static_cast<std::size_t>(count)) != 0)
            return -13;
    }
}

int verify_canary(int pid, char *message, std::size_t capacity) noexcept
{
    std::array<char, 128> expected{};
    std::array<char, 128> actual{};
    const int length = std::snprintf(expected.data(), expected.size(),
                                     "hello from the sandboxed app\n"
                                     "pid=%d before_open=%08x write_read=verified\n",
                                     pid, static_cast<std::uint32_t>(before_open_result));
    if (length <= 0 || static_cast<std::size_t>(length) >= expected.size())
        return -1;

    std::int64_t written = 0;
    {
        KernelFile output{sceKernelOpen(canary_path, open_write_create_truncate, file_mode_0666)};
        if (!output.valid())
            return output.get();
        written = sceKernelWrite(output.get(), expected.data(), static_cast<std::size_t>(length));
    }
    if (written != length)
        return -2;

    std::int64_t read_count = 0;
    {
        KernelFile input{sceKernelOpen(canary_path, open_read_only, 0)};
        if (!input.valid())
            return -3;
        read_count = sceKernelRead(input.get(), actual.data(), static_cast<std::size_t>(length));
    }
    if (read_count != length)
        return -4;
    for (int index = 0; index < length; ++index)
    {
        if (actual[static_cast<std::size_t>(index)] != expected[static_cast<std::size_t>(index)])
            return -5;
    }

    return std::snprintf(message, capacity, "SANDBOX AFTER OK pid=%d write=%d read=%d retained",
                         pid, static_cast<int>(written), static_cast<int>(read_count));
}
} // namespace

int main()
{
    const int pid = getpid();
    before_open_result = sceKernelOpen(canary_path, open_write_create_truncate, file_mode_0666);
    if (before_open_result >= 0)
    {
        (void)sceKernelClose(before_open_result);
        (void)sceKernelUnlink(canary_path);
        report("SANDBOX BEFORE UNEXPECTED: /data was already writable");
    }
    else
    {
        std::array<char, 128> before{};
        (void)std::snprintf(before.data(), before.size(), "SANDBOX BEFORE OK pid=%d open=%08x", pid,
                            static_cast<std::uint32_t>(before_open_result));
        report(before.data());
    }

    const int submission_result = submit_helper();
    std::array<char, 128> submission{};
    (void)std::snprintf(submission.data(), submission.size(),
                        "SANDBOX HELPER pid=%d submit=%08x loopback=127.0.0.1:%u", pid,
                        static_cast<std::uint32_t>(submission_result), elfldr_port);
    report(submission.data());

    for (;;)
    {
        std::array<char, 160> result{};
        if (verify_canary(pid, result.data(), result.size()) > 0)
        {
            report(result.data());
            for (;;)
                (void)sceKernelUsleep(2000000);
        }
        (void)sceKernelUsleep(250000);
    }
}
