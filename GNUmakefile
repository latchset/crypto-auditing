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
	${TARGETDIR}/${PROFILE}/crypto-auditing-event-broker \
	${TARGETDIR}/${PROFILE}/crypto-auditing-log-parser

conffiles = \
	dist/conf/agent.conf \
	dist/conf/event-broker.conf

.PHONY: all
all: $(programs)

agent/src/bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@-t && mv $@-t $@

$(programs): agent/src/bpf/vmlinux.h
	cargo build --target-dir="${TARGETDIR}" ${CARGO_ARGS}

.PHONY: install
install: all
	for f in $(conffiles); do \
		install -D -m 644 -S .orig -t /etc/crypto-auditing "$$f"; \
	done
	for f in $(programs); do \
		install -D -t ${DESTDIR}/usr/bin "$$f"; \
	done
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/crypto-auditing-agent.service
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/crypto-auditing-event-broker.service
	install -d ${DESTDIR}/var/lib/crypto-auditing
	install -d ${DESTDIR}/var/log/crypto-auditing

# This only runs tests without TPM access. See tests/run.sh for
# running full testsuite with swtpm.
.PHONY: check
check: all
	cargo test --target-dir="${TARGETDIR}"

.PHONY: clean
clean:
	cargo clean
	rm -f agent/src/bpf/vmlinux.h
