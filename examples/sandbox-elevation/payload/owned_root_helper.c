// clang-format off
/*
 * ps5-native-app-boilerplate - Owned-reference elevation helper.
 * Copyright (C) 2026 BlackBearReloaded
 *
 * Portions Copyright (c) 2026 Arksama (Team PHU)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Adapted from PS5-Lapy-JB-Daemon's guarded owned-root backend. A HELD state
 * deliberately retains every process whose directory ownership is ambiguous.
 */
// clang-format on
#include "elevation_protocol.h"
#include "owned_identity.h"
#include "donor_transaction.h"
#include "vnode_ref_probe.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern intptr_t kernel_get_ucred_prison(pid_t pid);

#ifndef TARGET_TITLE
#define TARGET_TITLE "PPSA99790"
#endif
#ifndef LAPY_SERVICE
#define LAPY_SERVICE 0
#endif
#ifndef LAPY_REQUIRE_CLIENT_RESULT
#define LAPY_REQUIRE_CLIENT_RESULT 1
#endif
#ifndef LAPY_MAX_REQUESTS
#define LAPY_MAX_REQUESTS 0
#endif
#ifndef LAPY_ELF_HELPER
#define LAPY_ELF_HELPER 0
#endif
#define TITLE_PREFIX TARGET_TITLE "_"
#define SANDBOX_BASE "/mnt/sandbox"
#define REQUEST_SUFFIX "/download0/elevate_proc"
#define ROOT_HOLD 0x1bcu
#define ROOT_USE 0x1c0u
#define PROC_PID_OFFSET 0xbcu
#define PROC_THREADS_HEAD 0x10u
#define PROC_SUSPCOUNT 0x3a0u
#define THREAD_PROC 0x08u
#define THREAD_NEXT 0x10u
#define FD_CDIR 0x08u
#define FD_REFCNT 0x34u
#define UCRED_REF 0x00u
#define UCRED_NGROUPS 0x10u
#define MAX_THREADS 256u
#define ROOT_LAYOUT_MAX_ATTEMPTS 3u
#define ROOT_LAYOUT_RETRY_DELAY_US 100000u
#define PTRACE_AUTHID UINT64_C(0x4800000000010003)
#define SYSTEM_AUTHID UINT64_C(0x4801000000000013)

enum
{
    PS5LOG_MARK = 0,
    PS5LOG_ERR = 1,
};

static int ps5log_init_default(const char *title, const char *name)
{
    return klog_printf("[sandbox-elevator] start title=%s name=%s\n", title, name) < 0;
}

static int ps5log_printf(int level, const char *format, ...)
{
    char message[768] = {0};
    va_list arguments;
    va_start(arguments, format);
    int result = vsnprintf(message, sizeof(message), format, arguments);
    va_end(arguments);
    klog_printf("[sandbox-elevator][%s] %s\n", level == PS5LOG_ERR ? "error" : "mark", message);
    return result;
}

static void ps5log_close(const char *reason)
{
    klog_printf("[sandbox-elevator] close reason=%s\n", reason);
}

struct child
{
    pid_t pid;
    intptr_t proc, fd;
    int stopped, reaped;
};

struct snapshot
{
    intptr_t proc, fd, ucred, prison, root, jail, cwd;
    intptr_t threads[MAX_THREADS];
    unsigned count, suspended;
    uint32_t fd_refs, cred_refs;
};

struct credentials
{
    uid_t uid, ruid, svuid;
    gid_t rgid, svgid;
    uint32_t ngroups;
    uint64_t authid;
    uint8_t attrs[32];
    uint8_t caps[16];
};

static int read_ptr(void *unused, intptr_t address, intptr_t *value)
{
    (void)unused;
    return kernel_copyout(address, value, sizeof(*value)) ? EFAULT : 0;
}

static int write_ptr(void *unused, intptr_t address, intptr_t value)
{
    (void)unused;
    return kernel_copyin(&value, address, sizeof(value)) ? EFAULT : 0;
}

static int read_root_counts(intptr_t root, struct lapy_vnode_ref_counts *out)
{
    if (kernel_copyout(root + ROOT_HOLD, &out->hold, sizeof(out->hold)) ||
        kernel_copyout(root + ROOT_USE, &out->use, sizeof(out->use)))
        return EFAULT;
    return 0;
}

static int sample_root(intptr_t root, const char *phase, struct lapy_vnode_ref_counts *out)
{
    int error = read_root_counts(root, out);
    if (error)
        return error;
    ps5log_printf(PS5LOG_MARK, "root_sample build=%s phase=%s hold=%u use=%u", LAPY_OWNED_ID, phase,
                  out->hold, out->use);
    return 0;
}

static int snapshot(pid_t pid, struct snapshot *out)
{
    pid_t observed = 0;
    intptr_t current = 0, owner = 0, next = 0;
    memset(out, 0, sizeof(*out));
    out->proc = kernel_get_proc(pid);
    if (!out->proc || kernel_copyout(out->proc + PROC_PID_OFFSET, &observed, sizeof(observed)) ||
        observed != pid)
        return ESRCH;
    out->fd = kernel_get_proc_filedesc(pid);
    out->ucred = kernel_get_proc_ucred(pid);
    out->prison = kernel_get_ucred_prison(pid);
    if (!out->fd || !out->ucred || !out->prison ||
        kernel_copyout(out->fd + FD_REFCNT, &out->fd_refs, sizeof(out->fd_refs)) ||
        kernel_copyout(out->ucred + UCRED_REF, &out->cred_refs, sizeof(out->cred_refs)) ||
        kernel_copyout(out->proc + PROC_SUSPCOUNT, &out->suspended, sizeof(out->suspended)) ||
        read_ptr(0, out->fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, &out->root) ||
        read_ptr(0, out->fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, &out->jail) ||
        read_ptr(0, out->fd + FD_CDIR, &out->cwd) ||
        read_ptr(0, out->proc + PROC_THREADS_HEAD, &current))
        return EFAULT;
    while (current)
    {
        if (out->count >= MAX_THREADS)
            return EOVERFLOW;
        for (unsigned i = 0; i < out->count; ++i)
            if (out->threads[i] == current)
                return ELOOP;
        out->threads[out->count++] = current;
        if (read_ptr(0, current + THREAD_PROC, &owner) ||
            read_ptr(0, current + THREAD_NEXT, &next) || owner != out->proc)
            return EFAULT;
        current = next;
    }
    return out->count ? 0 : EPROTO;
}

static int same_stop(const struct snapshot *a, const struct snapshot *b)
{
    return a->proc == b->proc && a->fd == b->fd && a->ucred == b->ucred && a->prison == b->prison &&
           a->root == b->root && a->jail == b->jail && a->cwd == b->cwd && a->fd_refs == 1 &&
           b->fd_refs == 1 && a->cred_refs == b->cred_refs && a->count == b->count &&
           a->count == a->suspended && b->count == b->suspended &&
           !memcmp(a->threads, b->threads, a->count * sizeof(a->threads[0]));
}

static int find_thread_credential_slot(const struct snapshot *state, size_t *offset)
{
    if (state->count != 1 || state->cred_refs != 2)
        return EBUSY;
    unsigned matches = 0;
    for (size_t at = 0x20; at < 0x400; at += sizeof(intptr_t))
    {
        intptr_t pointer = 0;
        if (read_ptr(0, state->threads[0] + at, &pointer))
            return EFAULT;
        if (pointer == state->ucred)
        {
            *offset = at;
            ++matches;
        }
    }
    return matches == 1 ? 0 : EPROTO;
}

static int private_process_credential(const struct snapshot *state, size_t thread_credential_offset)
{
    intptr_t thread_credential = 0;
    return state->count == 1 && state->cred_refs == 2 &&
           !read_ptr(0, state->threads[0] + thread_credential_offset, &thread_credential) &&
           thread_credential == state->ucred;
}

#if !LAPY_ELF_HELPER
static pid_t parse_pid(const char *message)
{
    const char *p = strstr(message, "\"PID\"");
    if (!p || !(p = strchr(p, ':')))
        return -1;
    ++p;
    while (*p == ' ' || *p == '\t' || *p == '"')
        ++p;
    errno = 0;
    char *end = 0;
    long value = strtol(p, &end, 10);
    return errno || end == p || value <= 1 || value > INT_MAX ? -1 : (pid_t)value;
}

static int find_request(char path[512], pid_t *pid, time_t started)
{
    DIR *directory = opendir(SANDBOX_BASE);
    if (!directory)
        return errno == ENOENT ? 0 : -(errno ? errno : EIO);
    struct dirent *entry;
    int result = 0;
    while ((entry = readdir(directory)))
    {
        if (TARGET_TITLE[0] == '*' && TARGET_TITLE[1] == 0)
        {
            if (strlen(entry->d_name) < 10 || strncmp(entry->d_name, "PPSA", 4) ||
                entry->d_name[9] != '_')
                continue;
            int valid = 1;
            for (int i = 4; i < 9; ++i)
                if (entry->d_name[i] < '0' || entry->d_name[i] > '9')
                    valid = 0;
            if (!valid)
                continue;
        }
        else if (strncmp(entry->d_name, TITLE_PREFIX, sizeof(TITLE_PREFIX) - 1))
            continue;
        int length = snprintf(path, 512, "%s/%s%s", SANDBOX_BASE, entry->d_name, REQUEST_SUFFIX);
        if (length <= 0 || length >= 512)
            continue;
        struct stat st;
        if (stat(path, &st) || st.st_size <= 0 || st.st_mtime < started)
            continue;
        FILE *file = fopen(path, "r");
        if (!file)
        {
            result = -(errno ? errno : EIO);
            break;
        }
        char message[512];
        size_t size = fread(message, 1, sizeof(message) - 1, file);
        int read_error = ferror(file);
        fclose(file);
        if (read_error || !size)
        {
            result = -EIO;
            break;
        }
        message[size] = 0;
        *pid = parse_pid(message);
        result = *pid > 1 ? 1 : -EINVAL;
        break;
    }
    closedir(directory);
    return result;
}

#if !LAPY_SERVICE || LAPY_REQUIRE_CLIENT_RESULT
static int client_result_path(const char *request, char result[512])
{
    size_t length = strlen(request), suffix = strlen(REQUEST_SUFFIX);
    if (length <= suffix || strcmp(request + length - suffix, REQUEST_SUFFIX))
        return EINVAL;
    int written =
        snprintf(result, 512, "%.*s/download0/lapy_owned_result", (int)(length - suffix), request);
    return written > 0 && written < 512 ? 0 : ENAMETOOLONG;
}

static int await_client_result(const char *path)
{
    for (unsigned i = 0; i < 100; ++i)
    {
        FILE *file = fopen(path, "r");
        if (file)
        {
            int data_ok = -1, open_errno = -1;
            int parsed = fscanf(file, "DATA_OK=%d OPEN_ERRNO=%d", &data_ok, &open_errno);
            fclose(file);
            if (parsed != 2)
            {
                usleep(100000);
                continue;
            }
            if (unlink(path))
                return errno ? errno : EIO;
            ps5log_printf(data_ok == 1 ? PS5LOG_MARK : PS5LOG_ERR,
                          "client_result build=%s data_rw=%d open_errno=%d", LAPY_OWNED_ID, data_ok,
                          open_errno);
            return data_ok == 1 ? 0 : EACCES;
        }
        if (errno != ENOENT)
            return errno ? errno : EIO;
        usleep(100000);
    }
    return ETIMEDOUT;
}
#endif
#endif /* !LAPY_ELF_HELPER */

static void donor_release_signal(int signal_number)
{
    (void)signal_number;
    _exit(0);
}

static void child_main(void)
{
    struct sigaction action;
    sigset_t release_signal;
    memset(&action, 0, sizeof(action));
    action.sa_handler = donor_release_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0))
        _exit(2);
    sigemptyset(&release_signal);
    sigaddset(&release_signal, SIGUSR1);
    if (sigprocmask(SIG_UNBLOCK, &release_signal, 0))
        _exit(3);
    /* waitpid(WUNTRACED) is the readiness acknowledgement. The handler is
     * installed before this stop, so an early release signal is safe. */
    if (kill(getpid(), SIGSTOP))
        _exit(4);
    for (;;)
        pause();
}

static int start_child(struct child *self)
{
    self->pid = rfork(RFPROC | RFFDG);
    if (self->pid == 0)
        child_main();
    if (self->pid < 0)
        return errno ? errno : EIO;
    for (unsigned i = 0; i < 100; ++i)
    {
        int status = 0;
        pid_t result = waitpid(self->pid, &status, WNOHANG | WUNTRACED);
        if (result == self->pid)
        {
            if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
            {
                if (WIFEXITED(status) || WIFSIGNALED(status))
                    self->reaped = 1;
                return EPROTO;
            }
            if (kill(self->pid, SIGCONT))
                return errno ? errno : EIO;
            for (unsigned resumed = 0; resumed < 100; ++resumed)
            {
                struct snapshot state;
                if (!snapshot(self->pid, &state) && !state.suspended)
                    return 0;
                usleep(10000);
            }
            return ETIMEDOUT;
        }
        if (result < 0)
            return errno ? errno : ECHILD;
        usleep(50000);
    }
    return ETIMEDOUT;
}

static int stop_child(struct child *self, intptr_t root)
{
    struct snapshot first, second;
    if (kill(self->pid, SIGSTOP))
        return errno ? errno : EIO;
    self->stopped = 1;
    for (unsigned i = 0; i < 100; ++i)
    {
        int error = snapshot(self->pid, &first);
        if (error)
            return error;
        if (first.proc != self->proc || first.fd != self->fd || first.fd_refs != 1 ||
            first.root != root || first.jail || first.cwd != root || first.count != 1)
            return EPROTO;
        if (first.suspended == 1)
        {
            usleep(50000);
            if ((error = snapshot(self->pid, &second)))
                return error;
            if (same_stop(&first, &second))
                return 0;
        }
        usleep(50000);
    }
    return ETIMEDOUT;
}

static int release_child(struct child *self)
{
    int status = 0;
    if (self->stopped)
    {
        if (kill(self->pid, SIGCONT))
            return errno ? errno : EIO;
        self->stopped = 0;
    }
    if (kill(self->pid, SIGUSR1))
        return errno ? errno : EIO;
    for (unsigned i = 0; i < 100; ++i)
    {
        pid_t result = waitpid(self->pid, &status, WNOHANG);
        if (result == self->pid)
        {
            self->reaped = 1;
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : EPROTO;
        }
        if (result < 0)
            return errno ? errno : ECHILD;
        usleep(50000);
    }
    return ETIMEDOUT;
}

static int cleanup_child(struct child *self)
{
    int error = 0;
    if (self->pid > 0 && !self->reaped)
    {
        kill(self->pid, SIGCONT);
        kill(self->pid, SIGKILL);
        if (waitpid(self->pid, 0, 0) == self->pid)
            self->reaped = 1;
        else
            error = errno ? errno : ECHILD;
    }
    return error;
}

/* The SDK resolves rootvnode per firmware, but does not expose these vnode
 * counter offsets. Check the assumed layout using a disposable native
 * RFPROC|RFFDG child before any target credential or directory write. */
static int validate_root_reference_layout_once(intptr_t root, intptr_t self_fd, unsigned attempt,
                                               int *retryable)
{
    struct child donor = {.pid = -1};
    struct snapshot observed;
    struct lapy_vnode_ref_counts before = {0}, during = {0}, after = {0};
    *retryable = 0;
    int error = sample_root(root, "layout_before", &before);
    if (error)
        return error;
    if (!before.hold || !before.use || before.hold > 1000000 || before.use > 1000000)
        return EPROTO;
    if ((error = start_child(&donor)))
        goto done;
    if ((error = snapshot(donor.pid, &observed)))
        goto done;
    if (observed.fd == self_fd || observed.fd_refs != 1 || observed.root != root || observed.jail ||
        observed.cwd != root || observed.count != 1 || observed.suspended)
    {
        error = EPROTO;
        goto done;
    }
    if ((error = sample_root(root, "layout_donor", &during)))
        goto done;
    if (!lapy_vnode_ref_probe_added_two(&before, &during))
    {
        /* The counters are global. A concurrent vnode release can hide the
         * donor's +2 even when its private filedesc snapshot is correct. */
        error = EPROTO;
        *retryable = 1;
    }
    if ((error = release_child(&donor)))
    {
        *retryable = 0;
        goto done;
    }
    if ((error = sample_root(root, "layout_released", &after)))
    {
        *retryable = 0;
        goto done;
    }
    if (!lapy_vnode_ref_probe_returned_to_baseline(&before, &after))
    {
        error = EPROTO;
        *retryable = 1;
    }
    else if (!*retryable)
    {
        error = 0;
    }
done:
{
    int cleanup_error = cleanup_child(&donor);
    if (cleanup_error)
    {
        error = cleanup_error;
        *retryable = 0;
    }
}
    ps5log_printf(
        error ? PS5LOG_ERR : PS5LOG_MARK,
        "root_layout_probe build=%s attempt=%u valid=%d error=%d retryable=%d before_hold=%u "
        "before_use=%u donor_hold=%u donor_use=%u released_hold=%u released_use=%u",
        LAPY_OWNED_ID, attempt, error == 0, error, *retryable, before.hold, before.use, during.hold,
        during.use, after.hold, after.use);
    return error;
}

static int validate_root_reference_layout(intptr_t root, intptr_t self_fd)
{
    unsigned attempts = 0;
    int error = EPROTO;
    for (unsigned attempt = 1; attempt <= ROOT_LAYOUT_MAX_ATTEMPTS; ++attempt)
    {
        int retryable = 0;
        attempts = attempt;
        error = validate_root_reference_layout_once(root, self_fd, attempt, &retryable);
        if (!error || !retryable)
            break;
        ps5log_printf(PS5LOG_MARK, "root_layout_retry build=%s attempt=%u next=%u error=%d",
                      LAPY_OWNED_ID, attempt, attempt + 1, error);
        if (attempt < ROOT_LAYOUT_MAX_ATTEMPTS)
            usleep(ROOT_LAYOUT_RETRY_DELAY_US);
    }
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "root_layout build=%s valid=%d error=%d attempts=%u", LAPY_OWNED_ID, error == 0,
                  error, attempts);
    return error;
}

static int validate_group_layout(intptr_t ucred)
{
    uint32_t stored = UINT32_MAX;
    int native = getgroups(0, 0);
    int error = native < 0 ? (errno ? errno : EIO) : 0;
    if (!error && kernel_copyout(ucred + UCRED_NGROUPS, &stored, sizeof(stored)))
        error = EFAULT;
    if (!error && stored != (uint32_t)native)
        error = EPROTO;
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK, "group_layout build=%s valid=%d error=%d",
                  LAPY_OWNED_ID, error == 0, error);
    return error;
}

static int save_credentials(pid_t pid, intptr_t ucred, struct credentials *out)
{
    out->uid = kernel_get_ucred_uid(pid);
    out->ruid = kernel_get_ucred_ruid(pid);
    out->svuid = kernel_get_ucred_svuid(pid);
    out->rgid = kernel_get_ucred_rgid(pid);
    out->svgid = kernel_get_ucred_svgid(pid);
    out->authid = kernel_get_ucred_authid(pid);
    return kernel_get_ucred_attrs(pid, out->attrs) || kernel_get_ucred_caps(pid, out->caps) ||
                   kernel_copyout(ucred + UCRED_NGROUPS, &out->ngroups, sizeof(out->ngroups))
               ? EFAULT
               : 0;
}

static int credentials_match(pid_t pid, const struct credentials *expected, intptr_t ucred)
{
    struct credentials found;
    return !save_credentials(pid, ucred, &found) && found.uid == expected->uid &&
           found.ruid == expected->ruid && found.svuid == expected->svuid &&
           found.rgid == expected->rgid && found.svgid == expected->svgid &&
           found.ngroups == expected->ngroups && found.authid == expected->authid &&
           !memcmp(found.attrs, expected->attrs, sizeof(found.attrs)) &&
           !memcmp(found.caps, expected->caps, sizeof(found.caps));
}

static int set_credentials(pid_t pid, intptr_t ucred, const struct credentials *value)
{
    int error = 0;
    error |= kernel_set_ucred_uid(pid, value->uid);
    error |= kernel_set_ucred_ruid(pid, value->ruid);
    error |= kernel_set_ucred_svuid(pid, value->svuid);
    error |= kernel_set_ucred_rgid(pid, value->rgid);
    error |= kernel_set_ucred_svgid(pid, value->svgid);
    error |= kernel_copyin(&value->ngroups, ucred + UCRED_NGROUPS, sizeof(value->ngroups));
    error |= kernel_set_ucred_authid(pid, value->authid);
    error |= kernel_set_ucred_caps(pid, value->caps);
    error |= kernel_set_ucred_attrs(pid, value->attrs);
    return !error && credentials_match(pid, value, ucred) ? 0 : EIO;
}

static int await_target_stop(pid_t pid, const struct snapshot *before, struct snapshot *stopped)
{
    int status = 0;
    for (unsigned i = 0; i < 100; ++i)
    {
        pid_t result = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (result == pid)
        {
            if (!WIFSTOPPED(status))
                return EPROTO;
            break;
        }
        if (result < 0)
            return errno ? errno : ECHILD;
        if (i == 99)
            return ETIMEDOUT;
        usleep(50000);
    }
    struct snapshot first;
    int error = snapshot(pid, &first);
    if (error)
        return error;
    usleep(50000);
    if ((error = snapshot(pid, stopped)))
        return error;
    return first.proc == before->proc && first.fd == before->fd && first.ucred == before->ucred &&
                   first.prison == before->prison && first.cred_refs == 2 &&
                   same_stop(&first, stopped)
               ? 0
               : EBUSY;
}

/* A traced title can be killed by its launcher while we prepare donors.
 * Only loss of the original proc identity proves that its credentials and
 * ptrace attachment no longer need restoring. Root transfer additionally
 * needs proof that both donors exited and the root counts settled. */
static int original_target_gone(pid_t pid, intptr_t original_proc)
{
    for (unsigned i = 0; i < 20; ++i)
    {
        if (kernel_get_proc(pid) != original_proc)
        {
            usleep(10000);
            if (kernel_get_proc(pid) != original_proc)
                return 1;
        }
        usleep(50000);
    }
    return 0;
}

static int transferred_target_gone(pid_t pid, intptr_t original_proc, const struct child *first,
                                   const struct child *second, intptr_t system_root,
                                   const struct lapy_vnode_ref_counts *baseline)
{
    struct lapy_vnode_ref_counts current;
    if (!first->reaped || !second->reaped || !original_target_gone(pid, original_proc))
        return 0;
    for (unsigned i = 0; i < 20; ++i)
    {
        if (!read_root_counts(system_root, &current) && current.hold == baseline->hold &&
            current.use == baseline->use)
        {
            usleep(50000);
            if (kernel_get_proc(pid) != original_proc && !read_root_counts(system_root, &current) &&
                current.hold == baseline->hold && current.use == baseline->use)
                return 1;
        }
        usleep(50000);
    }
    return 0;
}

static int run_one(pid_t pid, intptr_t system_root, const struct lapy_vnode_ref_counts *baseline,
                   size_t thread_credential_offset)
{
    struct child first = {.pid = -1};
    struct child second = {.pid = -1};
    struct snapshot before = {0}, stopped = {0}, confirmed = {0}, donor = {0};
    struct credentials original, elevated;
    struct lapy_slot_io io = {read_ptr, write_ptr, 0};
    struct lapy_vnode_ref_counts sample;
    uint64_t self_authid = 0;
    int error = 0, attached = 0, stopped_target = 0;
    int auth_changed = 0, cred_changed = 0, moved = 0, detached = 0;
    int roots_touched = 0;
    const char *stage = "target_preflight";

    if ((error = snapshot(pid, &before)))
        goto done;
    ps5log_printf(PS5LOG_MARK,
                  "target_state build=%s pid=%d fd_refs=%u cred_refs=%u threads=%u suspended=%u "
                  "root_old=%d jail_old=%d prison0=%d",
                  LAPY_OWNED_ID, pid, before.fd_refs, before.cred_refs, before.count,
                  before.suspended, before.root && before.root != system_root,
                  before.jail && before.jail != system_root,
                  before.prison == KERNEL_ADDRESS_PRISON0);
    if (before.fd_refs != 1 || before.suspended || !before.root || !before.jail ||
        before.root == system_root || before.jail == system_root ||
        before.prison != KERNEL_ADDRESS_PRISON0 ||
        !private_process_credential(&before, thread_credential_offset))
    {
        error = EBUSY;
        goto done;
    }
    if ((error = save_credentials(pid, before.ucred, &original)))
        goto done;
    ps5log_printf(PS5LOG_MARK,
                  "target_preflight build=%s pid=%d private_fd=1 private_cred=1 threads=%u "
                  "root_jail_alias=%d cwd_old=%d",
                  LAPY_OWNED_ID, pid, before.count, before.root == before.jail,
                  before.cwd == before.root);
    stage = "tracer_authority";
    self_authid = kernel_get_ucred_authid(getpid());
    if (!self_authid || kernel_set_ucred_authid(getpid(), PTRACE_AUTHID) ||
        kernel_get_ucred_authid(getpid()) != PTRACE_AUTHID)
    {
        error = EACCES;
        goto done;
    }
    auth_changed = 1;
    stage = "ptrace_attach";
    if (ptrace(PT_ATTACH, pid, 0, 0))
    {
        error = errno ? errno : EIO;
        goto done;
    }
    attached = 1;
    stage = "target_stop";
    if ((error = await_target_stop(pid, &before, &stopped)))
    {
        if (original_target_gone(pid, before.proc))
            goto target_gone;
        goto held;
    }
    stopped_target = 1;
    ps5log_printf(PS5LOG_MARK,
                  "target_stopped build=%s pid=%d threads=%u private_fd=1 private_cred=1",
                  LAPY_OWNED_ID, pid, stopped.count);
    if (!private_process_credential(&stopped, thread_credential_offset))
    {
        error = EBUSY;
        goto done;
    }
    stage = "credentials";
    elevated = original;
    elevated.uid = elevated.ruid = elevated.svuid = 0;
    elevated.rgid = elevated.svgid = 0;
    elevated.ngroups = 0;
    elevated.authid = SYSTEM_AUTHID;
    memset(elevated.caps, 0xff, sizeof(elevated.caps));
    elevated.attrs[0] |= UINT8_C(0x80);
    cred_changed = 1;
    if ((error = set_credentials(pid, stopped.ucred, &elevated)))
    {
        if (set_credentials(pid, stopped.ucred, &original))
        {
            if (original_target_gone(pid, before.proc))
                goto target_gone;
            goto held;
        }
        cred_changed = 0;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK, "credentials_applied build=%s private_cred=1 uid_zero=1 sony_full=1",
                  LAPY_OWNED_ID);
    stage = "first_donor";
    if ((error = start_child(&first)) || (error = snapshot(first.pid, &donor)))
        goto rollback;
    first.proc = donor.proc;
    first.fd = donor.fd;
    if (donor.fd_refs != 1 || donor.root != system_root || donor.jail || donor.cwd != system_root ||
        donor.count != 1 || donor.suspended)
    {
        error = EPROTO;
        goto rollback;
    }
    if ((error = stop_child(&first, system_root)))
        goto rollback;
    stage = "second_donor";
    if ((error = start_child(&second)) || (error = snapshot(second.pid, &donor)))
        goto rollback;
    second.proc = donor.proc;
    second.fd = donor.fd;
    if (donor.fd_refs != 1 || donor.root != system_root || donor.jail || donor.cwd != system_root ||
        donor.count != 1 || donor.suspended)
    {
        error = EPROTO;
        goto rollback;
    }
    if ((error = stop_child(&second, system_root)))
        goto rollback;
    int snapshot_error = snapshot(pid, &confirmed);
    if (snapshot_error || !same_stop(&stopped, &confirmed))
    {
        ps5log_printf(
            PS5LOG_ERR,
            "target_drift build=%s pid=%d snapshot_error=%d proc_same=%d fd_same=%d cred_same=%d "
            "prison_same=%d root_same=%d jail_same=%d cwd_same=%d threads_same=%d fd_refs=%u "
            "cred_refs=%u cred_refs_before=%u threads=%u threads_before=%u suspended=%u "
            "suspended_before=%u",
            LAPY_OWNED_ID, pid, snapshot_error, !snapshot_error && confirmed.proc == stopped.proc,
            !snapshot_error && confirmed.fd == stopped.fd,
            !snapshot_error && confirmed.ucred == stopped.ucred,
            !snapshot_error && confirmed.prison == stopped.prison,
            !snapshot_error && confirmed.root == stopped.root,
            !snapshot_error && confirmed.jail == stopped.jail,
            !snapshot_error && confirmed.cwd == stopped.cwd,
            !snapshot_error && confirmed.count == stopped.count &&
                !memcmp(confirmed.threads, stopped.threads,
                        confirmed.count * sizeof(confirmed.threads[0])),
            snapshot_error ? 0 : confirmed.fd_refs, snapshot_error ? 0 : confirmed.cred_refs,
            stopped.cred_refs, snapshot_error ? 0 : confirmed.count, stopped.count,
            snapshot_error ? 0 : confirmed.suspended, stopped.suspended);
        error = snapshot_error ? snapshot_error : EBUSY;
        goto rollback;
    }
    if ((error = sample_root(system_root, "donors_ready", &sample)))
        goto rollback;
    stage = "root_transfer";
    roots_touched = 1;
    enum lapy_replace_result result = lapy_replace_two_roots(
        &io, first.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, second.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR,
        stopped.fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, stopped.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        first.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR, second.fd + KERNEL_OFFSET_FILEDESC_FD_JDIR,
        system_root, stopped.root, stopped.jail);
    if (result == LAPY_REPLACE_HELD)
        goto held;
    if (result != LAPY_REPLACE_COMPLETE)
    {
        error = EPROTO;
        goto rollback;
    }
    moved = 1;
    if ((error = snapshot(pid, &confirmed)) || confirmed.proc != stopped.proc ||
        confirmed.fd != stopped.fd || confirmed.root != system_root ||
        confirmed.jail != system_root || confirmed.count != confirmed.suspended ||
        (error = snapshot(first.pid, &donor)) || donor.root || donor.jail != stopped.root ||
        (error = snapshot(second.pid, &donor)) || donor.root || donor.jail != stopped.jail)
    {
        error = EPROTO;
        goto held;
    }
    ps5log_printf(PS5LOG_MARK,
                  "roots_committed build=%s pid=%d two_native_refs=1 old_roots_received=1",
                  LAPY_OWNED_ID, pid);
    stage = "donor_release";
    if ((error = release_child(&first)) || (error = release_child(&second)))
        goto held;
    if ((error = sample_root(system_root, "donors_reaped", &sample)))
        goto held;
    if (!lapy_vnode_ref_probe_added_two(baseline, &sample))
    {
        error = EPROTO;
        goto held;
    }
    ps5log_printf(PS5LOG_MARK, "donor_balance build=%s expected_two=1", LAPY_OWNED_ID);
    stage = "detach";
    if (ptrace(PT_DETACH, pid, (caddr_t)1, 0))
    {
        error = errno ? errno : EIO;
        if (transferred_target_gone(pid, before.proc, &first, &second, system_root, baseline))
        {
            ps5log_printf(PS5LOG_MARK,
                          "target_gone_posttransfer build=%s pid=%d detach_error=%d "
                          "donors_reaped=1 root_balanced=1",
                          LAPY_OWNED_ID, pid, error);
            attached = 0;
            cred_changed = 0;
            stage = "target_gone_posttransfer";
            error = ESRCH;
            goto done;
        }
        goto held;
    }
    attached = 0;
    detached = 1;
    if (kill(pid, SIGCONT))
    {
        error = errno ? errno : EIO;
        goto done;
    }
    stage = "complete";
    goto done;
rollback:
    if (!roots_touched && original_target_gone(pid, before.proc))
        goto target_gone;
    if (cred_changed && set_credentials(pid, stopped.ucred, &original))
    {
        ps5log_printf(PS5LOG_ERR,
                      "credential_restore_failed build=%s stage=%s pid=%d original_proc_current=%d",
                      LAPY_OWNED_ID, stage, pid, kernel_get_proc(pid) == before.proc);
        if (!roots_touched && original_target_gone(pid, before.proc))
            goto target_gone;
        goto held;
    }
    cred_changed = 0;
done:
    if (attached)
    {
        if (!stopped_target)
        {
            if (!roots_touched && original_target_gone(pid, before.proc))
                goto target_gone;
            goto held;
        }
        if (ptrace(PT_DETACH, pid, (caddr_t)1, 0))
        {
            if (!roots_touched && original_target_gone(pid, before.proc))
                goto target_gone;
            goto held;
        }
        attached = 0;
        detached = 1;
        kill(pid, SIGCONT);
    }
    {
        int second_error = cleanup_child(&second);
        int first_error = cleanup_child(&first);
        if (second_error || first_error)
        {
            error = second_error ? second_error : first_error;
            goto held;
        }
    }
    if (auth_changed && (kernel_set_ucred_authid(getpid(), self_authid) ||
                         kernel_get_ucred_authid(getpid()) != self_authid))
        goto held;
    ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                  "request_result build=%s stage=%s error=%d pid=%d roots_moved=%d cred_changed=%d "
                  "detached=%d donors_reaped=%d",
                  LAPY_OWNED_ID, stage, error, pid, moved, cred_changed, detached,
                  first.reaped && second.reaped);
    return error ? error : 0;
target_gone:
    if (roots_touched)
        goto held;
    ps5log_printf(PS5LOG_MARK, "target_gone_pretransfer build=%s stage=%s pid=%d roots_touched=0",
                  LAPY_OWNED_ID, stage, pid);
    error = ESRCH;
    attached = 0;
    cred_changed = 0;
    goto done;
held:
    ps5log_printf(PS5LOG_ERR,
                  "daemon_held build=%s stage=%s error=%d pid=%d attached=%d target_stopped=%d "
                  "roots_moved=%d first_pid=%d second_pid=%d",
                  LAPY_OWNED_ID, stage, error, pid, attached, stopped_target, moved, first.pid,
                  second.pid);
    for (;;)
        sleep(1);
}

#if LAPY_ELF_HELPER
struct helper_app_info
{
    uint32_t app_id;
    uint64_t unknown1;
    char title_id[14];
    char unknown2[0x3c];
};
_Static_assert(sizeof(TARGET_TITLE) <= sizeof(((struct helper_app_info *)0)->title_id),
               "TARGET_TITLE does not fit sceKernelGetAppInfo");
extern int sceKernelGetAppInfo(pid_t pid, struct helper_app_info *info);

static int helper_transfer(int fd, void *buffer, size_t size, int writing)
{
    unsigned char *bytes = buffer;
    while (size)
    {
        ssize_t count = writing ? write(fd, bytes, size) : read(fd, bytes, size);
        if (count <= 0 || (size_t)count > size)
            return EIO;
        bytes += count;
        size -= (size_t)count;
    }
    return 0;
}

static int helper_message_matches(const struct lapy_elevation_message *message,
                                  const struct lapy_elevation_message *request, uint32_t kind)
{
    return message->magic == LAPY_ELEVATION_MAGIC && message->version == LAPY_ELEVATION_VERSION &&
           message->size == sizeof(*message) && message->kind == kind &&
           message->capability == request->capability && message->pid == request->pid;
}

static int helper_target_title_matches(pid_t pid)
{
    struct helper_app_info info;
    memset(&info, 0, sizeof(info));
    return sceKernelGetAppInfo(pid, &info) == 0 &&
           !memcmp(info.title_id, TARGET_TITLE, sizeof(TARGET_TITLE));
}

static uint32_t helper_status_for_error(int error)
{
    if (error == ESRCH)
        return LAPY_ELEVATION_TARGET_MISMATCH;
    if (error == EFAULT || error == ENOTSUP)
        return LAPY_ELEVATION_UNAVAILABLE;
    return LAPY_ELEVATION_APPLY_FAILED;
}

static int run_helper_request(intptr_t root, size_t thread_credential_offset)
{
    struct lapy_elevation_message request = {0}, prepare, prepared = {0};
    struct lapy_elevation_message response = {0};
    struct lapy_vnode_ref_counts baseline;
    int error = helper_transfer(STDIN_FILENO, &request, sizeof(request), 0);
    uint32_t status = LAPY_ELEVATION_OK;

    if (error)
        return 1;
    if (request.magic != LAPY_ELEVATION_MAGIC || request.size != sizeof(request))
        status = LAPY_ELEVATION_INVALID_REQUEST;
    else if (request.version != LAPY_ELEVATION_VERSION)
        status = LAPY_ELEVATION_UNSUPPORTED_VERSION;
    else if (request.kind != LAPY_ELEVATION_REQUEST || request.pid <= 1 ||
             request.pid > INT32_MAX || request.status)
        status = LAPY_ELEVATION_INVALID_REQUEST;
    else if (request.capability != LAPY_ELEVATION_FILESYSTEM)
        status = LAPY_ELEVATION_UNSUPPORTED_CAPABILITY;
    else if (!helper_target_title_matches((pid_t)request.pid))
        status = LAPY_ELEVATION_TARGET_MISMATCH;

    if (status != LAPY_ELEVATION_OK)
        goto respond;
    prepare = request;
    prepare.kind = LAPY_ELEVATION_PREPARE;
    prepare.status = LAPY_ELEVATION_OK;
    if ((error = helper_transfer(STDOUT_FILENO, &prepare, sizeof(prepare), 1)))
        return 1;

    if ((error = helper_transfer(STDIN_FILENO, &prepared, sizeof(prepared), 0)))
    {
        status = LAPY_ELEVATION_TRANSPORT_ERROR;
        goto respond;
    }
    if (!helper_message_matches(&prepared, &request, LAPY_ELEVATION_PREPARED))
    {
        status = LAPY_ELEVATION_PROTOCOL_ERROR;
        goto respond;
    }
    if (prepared.status != LAPY_ELEVATION_OK)
    {
        status = LAPY_ELEVATION_PREPARE_FAILED;
        goto respond;
    }
    /* Recheck the PID/title after the cooperative credential clone. */
    if (!helper_target_title_matches((pid_t)request.pid))
    {
        status = LAPY_ELEVATION_TARGET_MISMATCH;
        goto respond;
    }
    if ((error = sample_root(root, "helper_before", &baseline)))
    {
        status = LAPY_ELEVATION_UNAVAILABLE;
        goto respond;
    }
    error = run_one((pid_t)request.pid, root, &baseline, thread_credential_offset);
    status = error ? helper_status_for_error(error) : LAPY_ELEVATION_OK;

respond:
    response = request;
    response.kind = LAPY_ELEVATION_RESPONSE;
    response.status = status;
    if (helper_transfer(STDOUT_FILENO, &response, sizeof(response), 1))
        return 1;
    return status == LAPY_ELEVATION_OK ? 0 : 1;
}
#endif

int main(void)
{
#if !LAPY_ELF_HELPER
    char path[512] = {0};
#endif
#if !LAPY_SERVICE || LAPY_REQUIRE_CLIENT_RESULT
#if !LAPY_ELF_HELPER
    char result_path[512] = {0};
#endif
#endif
    pid_t pid = -1;
#if !LAPY_ELF_HELPER
    time_t started = time(NULL);
#endif
    intptr_t root = 0;
    struct snapshot self;
    struct lapy_vnode_ref_counts baseline = {0}, final = {0};
    intptr_t self_cred_before = 0;
    size_t thread_credential_offset = 0;
    int error = 0, acknowledged = 0;
    const char *stage = "preflight";
    int logging_ready = ps5log_init_default("LAPYOWN", "lapy-owned-root-daemon") == 0;
#if !LAPY_ELF_HELPER
    if (!logging_ready)
        return 2;
#endif
    ps5log_printf(PS5LOG_MARK,
                  "daemon_start build=%s firmware=%08x title=%s service=%d "
                  "require_client_result=%d max_requests=%d",
                  LAPY_OWNED_ID, kernel_get_fw_version(), TARGET_TITLE, LAPY_SERVICE,
                  LAPY_REQUIRE_CLIENT_RESULT, LAPY_MAX_REQUESTS);
    if (!kernel_get_fw_version() || KERNEL_OFFSET_PROC_P_PID != PROC_PID_OFFSET ||
        !KERNEL_ADDRESS_PRISON0 || !KERNEL_OFFSET_FILEDESC_FD_RDIR ||
        !KERNEL_OFFSET_FILEDESC_FD_JDIR)
    {
        error = ENOTSUP;
        goto done;
    }
    root = KERNEL_ADDRESS_ROOTVNODE ? kernel_get_root_vnode() : 0;
    if (!root)
    {
        intptr_t init_fd = kernel_get_proc_filedesc(1);
        if (init_fd)
            read_ptr(0, init_fd + KERNEL_OFFSET_FILEDESC_FD_RDIR, &root);
    }
    stage = "self_directory";
    if (!root || (error = snapshot(getpid(), &self)))
    {
        if (!error)
            error = EPROTO;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK,
                  "self_directory build=%s private_fd=%d root_system=%d jail_null=%d cwd_root=%d "
                  "cred_refs=%u threads=%u",
                  LAPY_OWNED_ID, self.fd_refs == 1, self.root == root, self.jail == 0,
                  self.cwd == root, self.cred_refs, self.count);
    if (self.fd_refs != 1 || self.root != root || self.jail || self.cwd != root)
    {
        if (!error)
            error = EPROTO;
        goto done;
    }
    self_cred_before = self.ucred;
    stage = "self_credential";
    if (seteuid(geteuid()))
    {
        error = errno ? errno : EIO;
        goto done;
    }
    if ((error = snapshot(getpid(), &self)))
        goto done;
    ps5log_printf(
        PS5LOG_MARK, "self_credential_state build=%s native_clone=%d private_cred=%d cred_refs=%u",
        LAPY_OWNED_ID, self.ucred != self_cred_before, self.cred_refs == 2, self.cred_refs);
    if (!self.ucred || self.ucred == self_cred_before || self.cred_refs != 2)
    {
        if (!error)
            error = EPROTO;
        goto done;
    }
    ps5log_printf(PS5LOG_MARK, "self_credential build=%s native_clone=1 refs=2", LAPY_OWNED_ID);
    stage = "group_layout";
    if ((error = validate_group_layout(self.ucred)))
        goto done;
    stage = "thread_credential_slot";
    if ((error = find_thread_credential_slot(&self, &thread_credential_offset)))
        goto done;
    ps5log_printf(PS5LOG_MARK, "thread_credential_slot build=%s offset=%zu", LAPY_OWNED_ID,
                  thread_credential_offset);
    stage = "root_layout";
    if ((error = validate_root_reference_layout(root, self.fd)))
        goto done;
#if LAPY_ELF_HELPER
    stage = "helper_request";
    const struct timeval timeout = {
        ELEVATION_IO_TIMEOUT_US / 1000000,
        ELEVATION_IO_TIMEOUT_US % 1000000,
    };
    if (setsockopt(STDIN_FILENO, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(STDOUT_FILENO, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
    {
        error = errno ? errno : EIO;
        goto done;
    }
    error = run_helper_request(root, thread_credential_offset) ? EIO : 0;
#elif LAPY_SERVICE
    for (unsigned completed = 0;;)
    {
        path[0] = 0;
        pid = -1;
        acknowledged = 0;
        stage = "find_request";
        int found = 0;
        for (unsigned polls = 0; polls < 600; ++polls)
        {
            found = find_request(path, &pid, started);
            if (found < 0)
            {
                error = -found;
                goto done;
            }
            if (found)
                break;
            usleep(100000);
        }
        if (!found)
            continue;
        stage = "request_baseline";
        if ((error = sample_root(root, "before_request", &baseline)))
            goto done;
        error = run_one(pid, root, &baseline, thread_credential_offset);
        if (path[0] && !unlink(path))
            acknowledged = 1;
        else if (error == ESRCH && errno == ENOENT)
            acknowledged = 1;
        else if (!error)
            error = errno ? errno : EIO;
        ps5log_printf(error ? PS5LOG_ERR : PS5LOG_MARK,
                      "service_request build=%s pid=%d completed=%u error=%d acknowledged=%d",
                      LAPY_OWNED_ID, pid, completed, error, acknowledged);
        if (!acknowledged)
            goto done;
        if (error == EBUSY || error == ESRCH)
        {
            error = 0;
            continue;
        }
        if (error)
            goto done;
        ++completed;
#if LAPY_REQUIRE_CLIENT_RESULT
        stage = "client_result";
        if ((error = client_result_path(path, result_path)))
            goto done;
        if ((error = await_client_result(result_path)))
            goto done;
#endif
        if (LAPY_MAX_REQUESTS && completed >= LAPY_MAX_REQUESTS)
        {
            stage = "service_limit";
            goto done;
        }
    }
#else
    if ((error = sample_root(root, "baseline", &baseline)))
        goto done;
    stage = "find_request";
    for (unsigned polls = 0; polls < 600; ++polls)
    {
        int found = find_request(path, &pid, started);
        if (found < 0)
        {
            error = -found;
            goto done;
        }
        if (found)
            break;
        if (polls == 599)
        {
            error = ETIMEDOUT;
            goto done;
        }
        usleep(100000);
    }
    stage = "request";
    if ((error = client_result_path(path, result_path)))
        goto done;
    error = run_one(pid, root, &baseline, thread_credential_offset);
    if (path[0] && !unlink(path))
        acknowledged = 1;
    else if (!error)
        error = errno ? errno : EIO;
    if (error)
        goto done;
    stage = "client_result";
    if ((error = await_client_result(result_path)))
        goto done;
    stage = "wait_title_exit";
    int title_gone = 0, root_settled = 0;
    for (unsigned i = 0; i < 600; ++i)
    {
        if (!title_gone)
        {
            errno = 0;
            title_gone = kill(pid, 0) < 0 && errno == ESRCH;
        }
        if (title_gone)
        {
            if ((error = read_root_counts(root, &final)))
                goto done;
            if (final.hold == baseline.hold && final.use == baseline.use)
            {
                root_settled = 1;
                break;
            }
        }
        usleep(100000);
    }
    if ((error = sample_root(root, root_settled ? "title_exited" : "exit_timeout", &final)))
        goto done;
    if (!root_settled)
    {
        error = ETIMEDOUT;
        goto done;
    }
    stage = "complete";
#endif
done:
    ps5log_printf(
        error ? PS5LOG_ERR : PS5LOG_MARK,
        "daemon_result build=%s stage=%s error=%d pid=%d acknowledged=%d root_balanced=%d",
        LAPY_OWNED_ID, stage, error, pid, acknowledged,
        !error && final.hold == baseline.hold && final.use == baseline.use);
    if (logging_ready)
        ps5log_close(error ? "daemon-failed" : "daemon-complete");
    return error ? 1 : 0;
}
