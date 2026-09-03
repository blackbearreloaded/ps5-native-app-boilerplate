/*
 * ps5-native-app-boilerplate - Minimal self-elevation example.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Requests data access from kstuff, writes a file under /data, reopens it,
 * and verifies its contents.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <kstuff.h>

namespace
{
constexpr char output_path[] = "/data/hello-from-sandbox.txt";
constexpr char output_text[] = "hello from the sandboxed app\n";
constexpr std::size_t output_size = sizeof(output_text) - 1;
constexpr std::uint32_t one_second_in_microseconds = 1'000'000;

extern "C"
{
    int sceKernelClose(int descriptor);
    int sceKernelOpen(const char *path, int flags, mode_t mode);
    std::int64_t sceKernelRead(int descriptor, void *buffer, std::size_t length);
    int sceKernelUsleep(std::uint32_t microseconds);
    std::int64_t sceKernelWrite(int descriptor, const void *buffer, std::size_t length);
}

class FileDescriptor
{
  public:
    explicit FileDescriptor(int value) noexcept : value_{value}
    {
    }

    ~FileDescriptor()
    {
        if (valid())
            (void)sceKernelClose(value_);
    }

    FileDescriptor(const FileDescriptor &) = delete;
    FileDescriptor &operator=(const FileDescriptor &) = delete;

    [[nodiscard]] bool valid() const noexcept
    {
        return value_ >= 0;
    }

    [[nodiscard]] int get() const noexcept
    {
        return value_;
    }

  private:
    int value_;
};

[[nodiscard]] int request_data_access() noexcept
{
    if (const int error = kstuff_probe(); error != 0)
        return error;
    return kstuff_request_profile(KSTUFF_PROFILE_DATA_ACCESS);
}

[[nodiscard]] bool write_and_verify_file() noexcept
{
    {
        FileDescriptor output{
            sceKernelOpen(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0666)};
        if (!output.valid() ||
            sceKernelWrite(output.get(), output_text, output_size) !=
                static_cast<std::int64_t>(output_size))
            return false;
    }

    std::array<char, output_size> actual{};
    FileDescriptor input{sceKernelOpen(output_path, O_RDONLY, 0)};
    return input.valid() &&
           sceKernelRead(input.get(), actual.data(), actual.size()) ==
               static_cast<std::int64_t>(actual.size()) &&
           std::memcmp(actual.data(), output_text, actual.size()) == 0;
}

[[noreturn]] void stay_alive() noexcept
{
    for (;;)
        (void)sceKernelUsleep(one_second_in_microseconds);
}
} // namespace

int main()
{
    if (request_data_access() == 0)
        (void)write_and_verify_file();

    stay_alive();
}
