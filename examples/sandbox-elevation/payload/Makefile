# ps5-native-app-boilerplate - Sandbox elevation helper build.
# Copyright (C) 2026 BlackBearReloaded
# SPDX-License-Identifier: GPL-3.0-or-later

ifdef PS5_PAYLOAD_SDK
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
include /opt/ps5-payload-sdk/toolchain/prospero.mk
endif

OUTPUT ?= ../../../build/sandbox-elevation/sandbox-elevator.elf
TARGET_TITLE ?= PPSA99790
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -I. \
	-DTARGET_TITLE=\"$(TARGET_TITLE)\" -DLAPY_ELF_HELPER=1 \
	-DLAPY_SERVICE=0 -DLAPY_REQUIRE_CLIENT_RESULT=0
LDFLAGS := -Wl,--build-id=none
SOURCES := owned_root_helper.c donor_transaction.c vnode_ref_probe.c
HEADERS := donor_transaction.h elevation_protocol.h owned_identity.h vnode_ref_probe.h

.PHONY: all clean FORCE

all: $(OUTPUT)

$(OUTPUT): FORCE $(SOURCES) $(HEADERS)
	@mkdir -p -- $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

FORCE:

clean:
	rm -f -- $(OUTPUT)
