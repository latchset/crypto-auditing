# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2023 The crypto-auditing developers.

RELEASE ?= 0
TARGETDIR ?= target
CONFFILE ?= agent/agent.conf

ifeq ($(RELEASE),1)
        PROFILE ?= release
        CARGO_ARGS = --release
else
        PROFILE ?= debug
        CARGO_ARGS =
endif

systemdsystemunitdir := $(shell pkg-config systemd --variable=systemdsystemunitdir)

programs = \
	${TARGETDIR}/${PROFILE}/crypto-auditing-agent \
	${TARGETDIR}/${PROFILE}/crypto-auditing-log-parser

.PHONY: all
all: $(programs)

agent/src/bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@-t && mv $@-t $@

$(programs): agent/src/bpf/vmlinux.h
	cargo build --target-dir="${TARGETDIR}" ${CARGO_ARGS}

.PHONY: install
install: all
	mkdir -p /etc/crypto-auditing/
	cp ${CONFFILE} /etc/crypto-auditing/agent.conf
	for f in $(programs); do \
		install -D -t ${DESTDIR}/usr/bin "$$f"; \
	done
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/crypto-auditing-agent.service

# This only runs tests without TPM access. See tests/run.sh for
# running full testsuite with swtpm.
.PHONY: check
check: all
	cargo test --target-dir="${TARGETDIR}"
