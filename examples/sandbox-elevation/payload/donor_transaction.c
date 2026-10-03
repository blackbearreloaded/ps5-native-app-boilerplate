// clang-format off
/*
 * ps5-native-app-boilerplate - Move-only owned vnode-reference transaction.
 * Copyright (C) 2026 BlackBearReloaded
 *
 * Portions Copyright (c) 2026 Arksama (Team PHU)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
// clang-format on
#include "donor_transaction.h"

static int inspect(const struct lapy_slot_io *io, intptr_t source_slot, intptr_t dest_slot,
                   intptr_t *source, intptr_t *dest)
{
    return io->read(io->context, source_slot, source) || io->read(io->context, dest_slot, dest);
}

enum lapy_move_result lapy_move_owned_ref(const struct lapy_slot_io *io, intptr_t source_slot,
                                          intptr_t empty_dest_slot, intptr_t expected_value)
{
    intptr_t source = 0, dest = 0;
    if (!io || !io->read || !io->write || !source_slot || !empty_dest_slot ||
        source_slot == empty_dest_slot || !expected_value ||
        inspect(io, source_slot, empty_dest_slot, &source, &dest) || source != expected_value ||
        dest != 0)
        return LAPY_MOVE_UNCHANGED;

    /* Clear first: a crash can strand a reference, but cannot make two
     * filedesc slots independently release the same single reference. */
    io->write(io->context, source_slot, 0);
    if (inspect(io, source_slot, empty_dest_slot, &source, &dest))
        return LAPY_MOVE_HELD;
    if (source == expected_value && dest == 0)
        return LAPY_MOVE_UNCHANGED;
    if (source != 0 || dest != 0)
        return LAPY_MOVE_HELD;

    io->write(io->context, empty_dest_slot, expected_value);
    if (inspect(io, source_slot, empty_dest_slot, &source, &dest))
        return LAPY_MOVE_HELD;
    if (source == 0 && dest == expected_value)
        return LAPY_MOVE_COMMITTED;
    if (source != 0 || dest != 0)
        return LAPY_MOVE_HELD;

    /* The destination remained null, so restoring source cannot duplicate
     * ownership. If even that readback fails, the owner must remain held. */
    io->write(io->context, source_slot, expected_value);
    if (inspect(io, source_slot, empty_dest_slot, &source, &dest))
        return LAPY_MOVE_HELD;
    return source == expected_value && dest == 0 ? LAPY_MOVE_UNCHANGED : LAPY_MOVE_HELD;
}

enum lapy_replace_result lapy_replace_owned_ref(const struct lapy_slot_io *io,
                                                intptr_t source_root_slot, intptr_t target_slot,
                                                intptr_t receiver_slot, intptr_t system_root,
                                                intptr_t expected_old)
{
    intptr_t source = 0, target = 0, receiver = 0;
    if (!io || !io->read || !io->write || !source_root_slot || !target_slot || !receiver_slot ||
        source_root_slot == target_slot || source_root_slot == receiver_slot ||
        target_slot == receiver_slot || !system_root ||
        io->read(io->context, source_root_slot, &source) ||
        io->read(io->context, target_slot, &target) ||
        io->read(io->context, receiver_slot, &receiver) || source != system_root ||
        target != expected_old || receiver != 0)
        return LAPY_REPLACE_UNCHANGED;

    if (expected_old)
    {
        enum lapy_move_result result =
            lapy_move_owned_ref(io, target_slot, receiver_slot, expected_old);
        if (result == LAPY_MOVE_UNCHANGED)
            return LAPY_REPLACE_UNCHANGED;
        if (result != LAPY_MOVE_COMMITTED)
            return LAPY_REPLACE_HELD;
    }

    enum lapy_move_result installed =
        lapy_move_owned_ref(io, source_root_slot, target_slot, system_root);
    if (installed == LAPY_MOVE_COMMITTED)
        return LAPY_REPLACE_COMPLETE;
    if (installed == LAPY_MOVE_HELD)
        return LAPY_REPLACE_HELD;
    if (!expected_old)
        return LAPY_REPLACE_UNCHANGED;

    /* The source move was proved unchanged; put the old reference back. */
    return lapy_move_owned_ref(io, receiver_slot, target_slot, expected_old) == LAPY_MOVE_COMMITTED
               ? LAPY_REPLACE_ROLLED_BACK
               : LAPY_REPLACE_HELD;
}

static int distinct_six(const intptr_t slots[6])
{
    for (unsigned i = 0; i < 6; ++i)
    {
        if (!slots[i])
            return 0;
        for (unsigned j = 0; j < i; ++j)
            if (slots[i] == slots[j])
                return 0;
    }
    return 1;
}

static enum lapy_replace_result undo_first(const struct lapy_slot_io *io, intptr_t source,
                                           intptr_t target, intptr_t receiver, intptr_t root,
                                           intptr_t old)
{
    if (lapy_move_owned_ref(io, target, source, root) != LAPY_MOVE_COMMITTED)
        return LAPY_REPLACE_HELD;
    if (old && lapy_move_owned_ref(io, receiver, target, old) != LAPY_MOVE_COMMITTED)
        return LAPY_REPLACE_HELD;
    return LAPY_REPLACE_ROLLED_BACK;
}

enum lapy_replace_result lapy_replace_two_roots(const struct lapy_slot_io *io,
                                                intptr_t first_source, intptr_t second_source,
                                                intptr_t target_root, intptr_t target_jail,
                                                intptr_t first_receiver, intptr_t second_receiver,
                                                intptr_t system_root, intptr_t old_root,
                                                intptr_t old_jail)
{
    const intptr_t slots[6] = {first_source, second_source,  target_root,
                               target_jail,  first_receiver, second_receiver};
    const intptr_t expected[6] = {system_root, system_root, old_root, old_jail, 0, 0};
    intptr_t observed = 0;
    if (!io || !io->read || !io->write || !system_root || !distinct_six(slots))
        return LAPY_REPLACE_UNCHANGED;
    for (unsigned i = 0; i < 6; ++i)
        if (io->read(io->context, slots[i], &observed) || observed != expected[i])
            return LAPY_REPLACE_UNCHANGED;

    enum lapy_replace_result first = lapy_replace_owned_ref(io, first_source, target_root,
                                                            first_receiver, system_root, old_root);
    if (first != LAPY_REPLACE_COMPLETE)
        return first;

    enum lapy_replace_result second = lapy_replace_owned_ref(
        io, second_source, target_jail, second_receiver, system_root, old_jail);
    if (second == LAPY_REPLACE_COMPLETE)
        return LAPY_REPLACE_COMPLETE;
    if (second == LAPY_REPLACE_HELD)
        return LAPY_REPLACE_HELD;
    return undo_first(io, first_source, target_root, first_receiver, system_root, old_root);
}
