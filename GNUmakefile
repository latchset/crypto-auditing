# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2023 The crypto-auditing developers.

RELEASE ?= 0
TARGETDIR ?= target

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
	${TARGETDIR}/${PROFILE}/crypto-auditing-client \
	${TARGETDIR}/${PROFILE}/crypto-auditing-event-broker \
	${TARGETDIR}/${PROFILE}/crypto-auditing-log-parser

conffiles = \
	dist/conf/agent.conf \
	dist/conf/client.conf \
	dist/conf/event-broker.conf

.PHONY: all
all: $(programs)

agent/src/bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@-t && mv $@-t $@

$(programs): agent/src/bpf/vmlinux.h
	cargo build --target-dir="${TARGETDIR}" ${CARGO_ARGS}

.PHONY: install-programs
install-programs: all
	for f in $(programs); do \
		install -D -t ${DESTDIR}/usr/bin "$$f"; \
	done

.PHONY: install
install: install-programs
	for f in $(conffiles); do \
		install -D -m 644 -S .orig -t /etc/crypto-auditing "$$f"; \
	done
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/crypto-auditing-agent.service
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/crypto-auditing-event-broker.service
	install -d ${DESTDIR}/run/crypto-auditing
	install -d ${DESTDIR}/var/log/crypto-auditing

.PHONY: check
check: all
	cargo test --target-dir="${TARGETDIR}"

.PHONY: clean
clean:
	cargo clean
	rm -f agent/src/bpf/vmlinux.h
