/*
 * ps5-native-app-boilerplate - libcurl support for PS5 native titles.
 * Copyright (C) 2026 BlackBearReloaded
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * PacBrew's libcurl (with OpenSSL, zlib, zstd and libpsl) links into a native
 * title, but needs console_curl.c beside it to run:
 *
 *   - getaddrinfo and friends on the system resolver (the SDK's stubs import
 *     them from a module a native title does not load: a call jumps to 0);
 *   - small stand-ins for libc functions the archives ask for;
 *   - an fcntl wrapper that answers curl's socket calls, which the console's
 *     libc refuses in a sandboxed title. Link with --wrap=fcntl:
 *     APP_WRAP_SYMBOLS += fcntl in the Makefile;
 *   - the path of the console's certificate list, for CURLOPT_CAINFO.
 *
 * In the Makefile: PACBREW_PACKAGES += libcurl and APP_WRAP_SYMBOLS += fcntl.
 * Set CURLOPT_NOSIGNAL on every handle. See docs/UPDATE_CHECK.md.
 */

#ifndef CONSOLE_CURL_H
#define CONSOLE_CURL_H

#ifdef __cplusplus
extern "C"
{
#endif

    /* The console's certificate authorities as a PEM file OpenSSL reads, for
     * CURLOPT_CAINFO: /system/common/cert/CA_LIST.cer with filesystem access
     * (elevated), /<sandbox word>/common/cert/CA_LIST.cer in the sandbox.
     * Checked again on every call, so it follows a change of root. */
    const char *console_curl_ca_file(void);

#ifdef __cplusplus
}
#endif

#endif /* CONSOLE_CURL_H */
