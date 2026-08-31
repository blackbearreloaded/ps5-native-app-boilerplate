# ps5-native-app-boilerplate - Owned process-memory test helper.
# Copyright (C) 2026 BlackBearReloaded
# SPDX-License-Identifier: GPL-3.0-or-later

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CXXFLAGS += -std=c++20 -O2 -Wall -Wextra -Werror

all: g2-process-helper.elf

g2-process-helper.elf: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f -- g2-process-helper.elf

.PHONY: all clean
