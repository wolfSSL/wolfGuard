# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
DESTDIR ?=
SYSCONFDIR ?= /etc
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
SYSTEMDUNITDIR ?= $(shell $(PKG_CONFIG) --variable=systemdsystemunitdir systemd 2>/dev/null || echo "$(PREFIX)/lib/systemd/system")
RUNSTATEDIR ?= /var/run
WITH_BASHCOMPLETION ?=
WITH_WGQUICK ?=
WITH_SYSTEMDUNITS ?=

ifeq ($(WITH_BASHCOMPLETION),)
ifneq ($(strip $(wildcard $(BASHCOMPDIR))),)
WITH_BASHCOMPLETION := yes
endif
endif
ifeq ($(WITH_WGQUICK),)
ifneq ($(strip $(wildcard $(BINDIR)/bash)),)
WITH_WGQUICK := yes
endif
ifneq ($(strip $(wildcard $(DESTDIR)/bin/bash)),)
WITH_WGQUICK := yes
endif
endif
ifeq ($(WITH_SYSTEMDUNITS),)
ifneq ($(strip $(wildcard $(SYSTEMDUNITDIR))),)
WITH_SYSTEMDUNITS := yes
endif
endif

PLATFORM ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

CFLAGS ?= -O3
ifneq ($(wildcard uapi/$(PLATFORM)/.),)
CFLAGS += -idirafter uapi/$(PLATFORM)
endif
CFLAGS += -std=gnu99 -D_GNU_SOURCE
CFLAGS += -Wall -Wextra
CFLAGS += -MMD -MP
CFLAGS += -DRUNSTATEDIR="\"$(RUNSTATEDIR)\""
ifeq ($(DEBUG),yes)
CFLAGS += -g
endif
WOLFGUARD_TOOLS_VERSION = $(patsubst v%,%,$(shell GIT_CEILING_DIRECTORIES="$(PWD)/../.." git describe --dirty 2>/dev/null))
ifneq ($(WOLFGUARD_TOOLS_VERSION),)
CFLAGS += -D'WOLFGUARD_TOOLS_VERSION="$(WOLFGUARD_TOOLS_VERSION)"'
endif
ifeq ($(PLATFORM),haiku)
LDLIBS += -lnetwork -lbsd
endif
ifeq ($(PLATFORM),windows)
CC := x86_64-w64-mingw32-gcc
CFLAGS += -Iwincompat/include -include wincompat/compat.h
LDLIBS += -lws2_32
wg-fips: wincompat/libc.o wincompat/init.o
endif

ifdef WOLFSSL_ROOT
CFLAGS += -I$(WOLFSSL_ROOT)/include
LDLIBS += -L$(WOLFSSL_ROOT)/lib -lwolfssl -Wl,-rpath=$(WOLFSSL_ROOT)/lib
else
CFLAGS += $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH} $(PKG_CONFIG) --cflags wolfssl)
LDLIBS += $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH} $(PKG_CONFIG) --libs wolfssl)
endif

ifdef EXTRA_CFLAGS
CFLAGS += $(EXTRA_CFLAGS)
endif

ifdef EXTRA_LDFLAGS
LDFLAGS += $(EXTRA_LDFLAGS)
endif

ifneq ($(V),1)
BUILT_IN_LINK.o := $(LINK.o)
LINK.o = @echo "  LD      $@";
LINK.o += $(BUILT_IN_LINK.o)
BUILT_IN_COMPILE.c := $(COMPILE.c)
COMPILE.c = @echo "  CC      $@";
COMPILE.c += $(BUILT_IN_COMPILE.c)
BUILT_IN_RM := $(RM)
RM := @a() { echo "  CLEAN   $$@"; $(BUILT_IN_RM) "$$@"; }; a
endif

wg-fips: $(sort $(patsubst %.c,%.o,$(wildcard *.c)))

clean:
	$(RM) wg-fips *.o *.d

# WolfGuard installs symlinks for wg and wg-quick, mapping them to wg-fips and
# wg-fips-quick respectively.
#
# If regular files are found there at install time, they are assumed to be
# WireGuard executables, and are renamed accordingly.
#
# After installation, WireGuard wg is available as wg-wireguard, and WireGuard
# wg-quick as wg-wireguard-quick.

install: wg-fips
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 wg-fips "$(DESTDIR)$(BINDIR)/wg-fips"
	@if test -f "$(DESTDIR)$(BINDIR)/wg" && ! test -h "$(DESTDIR)$(BINDIR)/wg"; then mv --backup --verbose "$(DESTDIR)$(BINDIR)/wg" "$(DESTDIR)$(BINDIR)/wg-wireguard"; fi
	@if [ ! -e "$(DESTDIR)$(BINDIR)/wg" ]; then ln -s wg-fips "$(DESTDIR)$(BINDIR)/wg"; fi
	@install -v -d "$(DESTDIR)$(MANDIR)/man8" && install -v -m 0644 man/wg-fips.8 "$(DESTDIR)$(MANDIR)/man8/wg-fips.8"
	@if test -f "$(DESTDIR)$(MANDIR)/man8/wg.8" && ! test -h "$(DESTDIR)$(MANDIR)/man8/wg.8"; then mv --backup --verbose "$(DESTDIR)$(MANDIR)/man8/wg.8" "$(DESTDIR)$(MANDIR)/man8/wg-wireguard.8"; fi
	@if [ ! -e "$(DESTDIR)$(MANDIR)/man8/wg.8" ]; then ln -s wg-fips.8 "$(DESTDIR)$(MANDIR)/man8/wg.8"; fi
	@[ "$(WITH_BASHCOMPLETION)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(BASHCOMPDIR)" && install -v -m 0644 completion/wg-fips.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/wg"
	@[ "$(WITH_WGQUICK)" = "yes" ] || exit 0; \
	install -v -m 0755 wg-fips-quick/$(PLATFORM).bash "$(DESTDIR)$(BINDIR)/wg-fips-quick" && install -v -m 0700 -d "$(DESTDIR)$(SYSCONFDIR)/wolfguard"
	@[ "$(WITH_WGQUICK)" = "yes" ] || exit 0; \
	if test -f "$(DESTDIR)$(BINDIR)/wg-quick" && ! test -h "$(DESTDIR)$(BINDIR)/wg-quick"; then \
		mv --backup --verbose "$(DESTDIR)$(BINDIR)/wg-quick" "$(DESTDIR)$(BINDIR)/wg-wireguard-quick" && \
		mv --backup --verbose "$(DESTDIR)$(BINDIR)/wg-wireguard-quick" "$(DESTDIR)$(BINDIR)/wg-wireguard-quick.unpatched" && \
		sed 's/wg show/wg-wireguard show/g;s/wg set/wg-wireguard set/g' "$(DESTDIR)$(BINDIR)/wg-wireguard-quick.unpatched" > "$(DESTDIR)$(BINDIR)/wg-wireguard-quick"; \
	fi
	@if [ ! -e "$(DESTDIR)$(BINDIR)/wg-quick" ]; then ln -s wg-fips-quick "$(DESTDIR)$(BINDIR)/wg-quick"; fi
	@[ "$(WITH_WGQUICK)" = "yes" ] || exit 0; \
	install -v -m 0644 man/wg-fips-quick.8 "$(DESTDIR)$(MANDIR)/man8/wg-fips-quick.8" || exit $$?; \
	if test -f "$(DESTDIR)$(MANDIR)/man8/wg-quick.8" && ! test -h "$(DESTDIR)$(MANDIR)/man8/wg-quick.8"; then \
		mv --backup --verbose "$(DESTDIR)$(MANDIR)/man8/wg-quick.8" "$(DESTDIR)$(MANDIR)/man8/wg-wireguard-quick.8"; \
	fi
	@if [ ! -e "$(DESTDIR)$(MANDIR)/man8/wg-quick.8" ]; then ln -s wg-fips-quick.8 "$(DESTDIR)$(MANDIR)/man8/wg-quick.8"; fi
	@[ "$(WITH_WGQUICK)" = "yes" -a "$(WITH_BASHCOMPLETION)" = "yes" ] || exit 0; \
	install -v -m 0644 completion/wg-fips-quick.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/wg-fips-quick"
	@[ "$(WITH_WGQUICK)" = "yes" -a "$(WITH_SYSTEMDUNITS)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(SYSTEMDUNITDIR)" && install -v -m 0644 systemd/* "$(DESTDIR)$(SYSTEMDUNITDIR)/"

check: clean
	scan-build --html-title=wolfguard-tools -maxloop 100 --view --keep-going $(MAKE) wg-fips

all: wg-fips
.DEFAULT_GOAL: all
.PHONY: clean install check

-include *.d
