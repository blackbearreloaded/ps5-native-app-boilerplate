/*
 * ps5-native-app-boilerplate - Exact-title sandbox elevation helper.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Elevates only the PPSA99790 proof process, verifies each changed field, and
 * exits immediately. It is submitted to an already-running elfldr by the app.
 */

#include <array>
#include <cstdint>
#include <cstring>

extern "C"
{
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <ps5/payload.h>
#include <unistd.h>
}

namespace
{
constexpr char target_title_id[] = "PPSA99790";
constexpr std::uint64_t system_auth_id = UINT64_C(0x4801000000000013);
constexpr unsigned poll_attempts = 120;
constexpr useconds_t poll_delay_us = 250000;
constexpr std::uintptr_t ucred_groups_offset = 0x10;

struct AppInfo
{
    std::uint32_t app_id;
    std::uint64_t unknown1;
    char title_id[14];
    char unknown2[0x3c];
};

extern "C" int sceKernelGetAppInfo(pid_t pid, AppInfo *info);

bool has_target_title(const char *title_id) noexcept
{
    constexpr auto length = sizeof(target_title_id) - 1;
    return std::strncmp(title_id, target_title_id, length) == 0 && title_id[length] == '\0';
}

pid_t find_target() noexcept
{
    std::intptr_t process = 0;
    if (kernel_copyout(KERNEL_ADDRESS_ALLPROC, &process, sizeof(process)) != 0)
        return -1;

    for (unsigned guard = 0; process != 0 && guard < 4096; ++guard)
    {
        pid_t pid = -1;
        if (kernel_copyout(process + KERNEL_OFFSET_PROC_P_PID, &pid, sizeof(pid)) != 0)
            return -1;

        if (pid > 0)
        {
            AppInfo info{};
            if (sceKernelGetAppInfo(pid, &info) == 0 && has_target_title(info.title_id))
                return pid;
        }

        std::intptr_t next = 0;
        if (kernel_copyout(process, &next, sizeof(next)) != 0)
            return -1;
        process = next;
    }
    return -1;
}

bool all_bytes_are(const std::array<std::uint8_t, 16> &values, std::uint8_t expected) noexcept
{
    for (const auto value : values)
    {
        if (value != expected)
            return false;
    }
    return true;
}

int elevate_and_verify(pid_t pid) noexcept
{
    const std::intptr_t ucred = kernel_get_proc_ucred(pid);
    const std::intptr_t root_vnode = kernel_get_root_vnode();
    if (ucred == 0 || root_vnode == 0)
        return -1;

    const std::uint32_t zero = 0;
    std::array<std::uint8_t, 16> full_caps{};
    full_caps.fill(0xff);
    std::array<std::uint8_t, 32> attrs{};
    if (kernel_get_ucred_attrs(pid, attrs.data()) != 0)
        return -2;
    attrs[3] = static_cast<std::uint8_t>(attrs[3] | 0x80);

    int failures = 0;
    failures += kernel_set_ucred_uid(pid, 0) != 0;
    failures += kernel_set_ucred_ruid(pid, 0) != 0;
    failures += kernel_set_ucred_svuid(pid, 0) != 0;
    failures += kernel_copyin(&zero, ucred + ucred_groups_offset, sizeof(zero)) != 0;
    failures += kernel_set_ucred_rgid(pid, 0) != 0;
    failures += kernel_set_proc_rootdir(pid, root_vnode) != 0;
    failures += kernel_set_proc_jaildir(pid, root_vnode) != 0;
    failures += kernel_set_ucred_authid(pid, system_auth_id) != 0;
    failures += kernel_set_ucred_caps(pid, full_caps.data()) != 0;
    failures += kernel_set_ucred_attrs(pid, attrs.data()) != 0;
    if (failures != 0)
        return -3;

    std::uint32_t groups = UINT32_MAX;
    std::array<std::uint8_t, 16> verified_caps{};
    std::array<std::uint8_t, 32> verified_attrs{};
    failures += kernel_copyout(ucred + ucred_groups_offset, &groups, sizeof(groups)) != 0;
    failures += kernel_get_ucred_caps(pid, verified_caps.data()) != 0;
    failures += kernel_get_ucred_attrs(pid, verified_attrs.data()) != 0;
    failures += kernel_get_ucred_uid(pid) != 0;
    failures += kernel_get_ucred_ruid(pid) != 0;
    failures += kernel_get_ucred_svuid(pid) != 0;
    failures += kernel_get_ucred_rgid(pid) != 0;
    failures += groups != 0;
    failures += kernel_get_ucred_authid(pid) != system_auth_id;
    failures += !all_bytes_are(verified_caps, 0xff);
    failures += (verified_attrs[3] & 0x80) == 0;
    failures += kernel_get_proc_rootdir(pid) != root_vnode;
    failures += kernel_get_proc_jaildir(pid) != root_vnode;
    return failures == 0 ? 0 : -4;
}
} // namespace

int main()
{
    const payload_args_t *args = payload_get_args();
    if (args == nullptr || args->kdata_base_addr == 0)
    {
        klog_puts("[sandbox-elevator] missing elfldr payload arguments\n");
        return 1;
    }

    klog_printf("[sandbox-elevator] start fw=%08x target=%s\n", kernel_get_fw_version(),
                target_title_id);
    for (unsigned attempt = 0; attempt < poll_attempts; ++attempt)
    {
        const pid_t pid = find_target();
        if (pid > 0)
        {
            const int result = elevate_and_verify(pid);
            klog_printf("[sandbox-elevator] pid=%d result=%d\n", static_cast<int>(pid), result);
            return result == 0 ? 0 : 2;
        }
        usleep(poll_delay_us);
    }

    klog_printf("[sandbox-elevator] target %s not found\n", target_title_id);
    return 3;
}
