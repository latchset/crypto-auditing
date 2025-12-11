# crypto-auditing-client

[![crates.io badge](https://img.shields.io/crates/v/crypto-auditing-client.svg)](https://crates.io/crates/crypto-auditing-client)

This crate provides the `crau-client` executable. To see the whole architecture, see the design [document](https://github.com/latchset/crypto-auditing/blob/main/docs/architecture.md).

This requires `crau-event-broker` running on the system.  To see how
to set up and run the event-broker, see the
[instructions](https://github.com/latchset/crypto-auditing/blob/main/README.md#running).

## Usage

```console
$ cargo install crypto-auditing-client
$ crau-client --scope tls --format json
$ crau-client --scope tls --format cbor --output audit.cborseq
```
