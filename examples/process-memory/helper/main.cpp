/*
 * ps5-native-app-boilerplate - Owned process-memory test helper.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Publishes one sentinel address, observes its temporary replacement, verifies
 * restoration, and exits without exposing any general process-memory service.
 */

#include <fcntl.h>
#include <ps5/klog.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

namespace
{
constexpr char info_path[] = "/data/g2-process-helper.bin";
constexpr char info_temporary_path[] = "/data/g2-process-helper.bin.tmp";
constexpr char result_path[] = "/data/g2-process-helper-result.txt";
constexpr uint64_t helper_magic = UINT64_C(0x325245504c454847);
constexpr uint32_t helper_version = 1;
constexpr uint64_t helper_cookie = UINT64_C(0x6f574e4544473241);
constexpr uint64_t original_value = UINT64_C(0x1122334455667788);
constexpr uint64_t replacement_value = UINT64_C(0xa55aa55a5aa55aa5);
constexpr unsigned int poll_interval_microseconds = 1000;
constexpr unsigned int poll_limit = 300000;

struct HelperInfo
{
    uint64_t magic;
    uint32_t version;
    int32_t pid;
    uint64_t address;
    uint64_t original;
    uint64_t replacement;
    uint64_t cookie;
};

static_assert(sizeof(HelperInfo) == 48);

alignas(uint64_t) volatile uint64_t marker = original_value;

bool write_exact(int descriptor, const void *buffer, size_t length)
{
    const auto *cursor = static_cast<const uint8_t *>(buffer);
    while (length != 0)
    {
        const ssize_t written = write(descriptor, cursor, length);
        if (written <= 0)
            return false;
        cursor += static_cast<size_t>(written);
        length -= static_cast<size_t>(written);
    }
    return true;
}

bool write_info()
{
    const HelperInfo info{
        helper_magic,   helper_version,    getpid(),     reinterpret_cast<uintptr_t>(&marker),
        original_value, replacement_value, helper_cookie};
    unlink(info_temporary_path);
    const int descriptor = open(info_temporary_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (descriptor < 0)
        return false;
    const bool written = write_exact(descriptor, &info, sizeof(info));
    const bool closed = close(descriptor) == 0;
    if (!written || !closed || rename(info_temporary_path, info_path) != 0)
    {
        unlink(info_temporary_path);
        return false;
    }
    return true;
}

void write_result(const char *result)
{
    const int descriptor = open(result_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (descriptor < 0)
        return;
    char text[160]{};
    const int length = snprintf(text, sizeof(text), "result=%s pid=%d marker=%016lx\n", result,
                                getpid(), static_cast<unsigned long>(marker));
    if (length > 0 && static_cast<size_t>(length) < sizeof(text))
        (void)write_exact(descriptor, text, static_cast<size_t>(length));
    (void)close(descriptor);
}

} // namespace

int main()
{
    unlink(info_path);
    unlink(result_path);
    if (!write_info())
    {
        klog_puts("[G2-HELPER] failed to publish helper info\n");
        return 1;
    }

    klog_printf("[G2-HELPER] ready pid=%d address=%p\n", getpid(),
                const_cast<const uint64_t *>(&marker));
    bool observed_replacement = false;
    for (unsigned int poll = 0; poll < poll_limit; ++poll)
    {
        const uint64_t value = marker;
        if (!observed_replacement && value == replacement_value)
        {
            observed_replacement = true;
            klog_puts("[G2-HELPER] replacement observed\n");
        }
        else if (observed_replacement && value == original_value)
        {
            write_result("PASS");
            klog_puts("[G2-HELPER] restoration observed; PASS\n");
            return 0;
        }
        else if (value != original_value && value != replacement_value)
        {
            write_result("FAIL_UNEXPECTED_VALUE");
            klog_puts("[G2-HELPER] unexpected marker value\n");
            return 2;
        }
        usleep(poll_interval_microseconds);
    }

    write_result(observed_replacement ? "FAIL_NOT_RESTORED" : "FAIL_NOT_MODIFIED");
    klog_puts("[G2-HELPER] timed out\n");
    return 3;
}
