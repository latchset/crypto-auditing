# crypto-auditing-client

[![crates.io badge](https://img.shields.io/crates/v/crypto-auditing-client.svg)](https://crates.io/crates/crypto-auditing-client)

This crate provides the crypto-auditing-client executable. To see the whole architecture, see the design [document](https://github.com/latchset/crypto-auditing/blob/main/docs/architecture.md).

This requires crypto-auditing-event-broker running on the system.  To
see how to set up and run the event-broker, see the
[instructions](https://github.com/latchset/crypto-auditing/blob/main/README.md#running).

## Usage

```console
$ cargo install crypto-auditing-client
$ crypto-auditing-client --scope tls --format json
$ crypto-auditing-client --scope tls --format cbor --output audit.cborseq
```
