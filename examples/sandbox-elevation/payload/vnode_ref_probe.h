// clang-format off
/*
 * ps5-native-app-boilerplate - Runtime vnode-reference layout checks.
 * Copyright (C) 2026 BlackBearReloaded
 *
 * Portions Copyright (c) 2026 Arksama (Team PHU)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
// clang-format on
#ifndef LAPY_VNODE_REF_PROBE_H
#define LAPY_VNODE_REF_PROBE_H

#include <stdint.h>

struct lapy_vnode_ref_counts
{
    uint32_t hold;
    uint32_t use;
};

/* Strict observations for a disposable RFPROC|RFFDG reference probe.
 * Unrelated vnode activity makes a sample inconclusive; callers may retry a
 * bounded probe, but must never relax either ownership delta. */
int lapy_vnode_ref_probe_added_two(const struct lapy_vnode_ref_counts *before,
                                   const struct lapy_vnode_ref_counts *with_donor);
int lapy_vnode_ref_probe_returned_to_baseline(const struct lapy_vnode_ref_counts *before,
                                              const struct lapy_vnode_ref_counts *after_release);

#endif
