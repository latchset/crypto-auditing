#!/usr/bin/env bash

set -uexo pipefail

SOURCE_DIR=$1
VERSION=$2
OUT_DIR=$3

pushd $SOURCE_DIR
	[ -e Cargo.lock ]

	git archive HEAD \
		--format=tar \
		--prefix=crypto-auditing-$VERSION/ \
		| zstd -9 > $OUT_DIR/crypto-auditing-$VERSION.tar.zstd


	rm -rf vendor
	cargo vendor --versioned-dirs vendor
	tar c vendor \
		| zstd -9 \
		> $OUT_DIR/crypto-auditing-$VERSION-vendor.tar.zstd

	rm -rf vendor
popd
