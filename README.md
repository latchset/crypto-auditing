# crypto-auditing

[![Rust](https://github.com/latchset/crypto-auditing/actions/workflows/rust.yml/badge.svg)](https://github.com/latchset/crypto-auditing/actions/workflows/rust.yml)

## Introduction

This project provides the infrastructure needed to audit
cryptographic operations performed by system crypto libraries. It
does so with BPF USDT probes placed at specific entry points in those
libraries, which capture data as the libraries are used by user-space
processes across the system, for later analysis.

The primary use case of this project is to help organizations migrate
to post-quantum cryptography. Since post-quantum algorithms are
relatively new and not every application supports them yet, a forced
switch away from classical cryptography is impractical. To make the
transition smoother, crypto-auditing can be used at run time to
identify where classical cryptography is still in use.

The design of crypto-auditing prioritizes privacy, efficiency, and
maintainability: user activity remains confidential, the impact on
performance is minimal, and collection rules are easy to manage.

More detailed design documents are available at the following links:

- [Objectives and high-level design](docs/objectives.md)
- [Architecture](docs/architecture.md)
- [Logging format for primary event logs](docs/logging-format.md)
- [Event keys registry](docs/registry.md)
- [Event schema](docs/schema.md)
- [USDT probe points](docs/probe-points.md)
- [Measuring performance impact](docs/performance.md)

## Installation

1. Install the latest Rust toolchain
2. Install the dependencies (libbpf 1.1.1 or later is required)
```console
$ sudo dnf install bpftool make libbpf-devel llvm-devel rustfmt
```
3. Build the programs
```console
$ make
```
4. Install the programs
```console
$ sudo make install
```

## Running

1. Create a dedicated user and group (e.g., crypto-auditing:crypto-auditing)
```console
$ sudo groupadd crypto-auditing
$ sudo useradd -g crypto-auditing crypto-auditing
```
2. Set the user and group in the agent's systemd unit, `/lib/systemd/system/crau-agent.service`:
```ini
User=crypto-auditing
Group=crypto-auditing
```
3. Configure the agent in `/etc/crypto-auditing/agent.conf`:
```toml
library = ["/path/to/installation/lib64/libgnutls.so.30"]
user = "crypto-auditing:crypto-auditing"
```
4. Start the agent
```console
$ sudo systemctl daemon-reload
$ sudo systemctl start crau-agent.service
```
5. Run the monitor
```console
$ crau-monitor
```
6. In another terminal, run any program that uses an instrumented
   library, such as GnuTLS in Fedora Linux 43 or later (the
   credentials below are from the GnuTLS source tree)
```console
$ gnutls-serv --x509certfile=doc/credentials/x509/cert-rsa-pss.pem --x509keyfile=doc/credentials/x509/key-rsa-pss.pem &
$ gnutls-cli --x509cafile=doc/credentials/x509/ca.pem localhost -p 5556
^C
$ gnutls-cli --x509cafile=doc/credentials/x509/ca.pem localhost -p 5556 --priority NORMAL:-VERS-TLS1.3
```

## Inspecting logs

In the above example, the agent writes the events to a log file on
the system (`/var/log/crypto-auditing/audit.cborseq` by default),
which can be parsed and printed with `crau-query`:

```console
$ crau-query
[
  {
    "context": "88b7dd7bb10fc0cb92fba1b1d29845b5",
    "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
    "executable": "gnutls-cli",
    "start": 1795699631.408859,
    "end": 1795699631.410625,
    "events": {
      "name": "tls::handshake",
      "tls::ciphersuite": 4866,
      "tls::protocol_version": 772,
      "tls::role": "client"
    },
    "spans": [
      {
        "context": "8ffbea6903587c06f75ec75616e949fe",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-cli",
        "start": 1795699631.409042,
        "end": 1795699631.409454,
        "events": {
          "name": "tls::key_exchange",
          "tls::group": 4588
        }
      },
      {
        "context": "683ae04c31deba23437c6f22ca5a4a5d",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-cli",
        "start": 1795699631.410405,
        "end": 1795699631.410411,
        "events": {
          "name": "tls::verify",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  },
  {
    "context": "0d185bb96a48985821682ea9e6d5bf99",
    "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
    "executable": "gnutls-serv",
    "start": 1795699631.41073,
    "end": 1795699631.412496,
    "events": {
      "name": "tls::handshake",
      "tls::ciphersuite": 4866,
      "tls::protocol_version": 772,
      "tls::role": "server"
    },
    "spans": [
      {
        "context": "5a6da95cde5576570659f87e46d02495",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-serv",
        "start": 1795699631.410913,
        "end": 1795699631.411325,
        "events": {
          "name": "tls::key_exchange",
          "tls::group": 4588
        }
      },
      {
        "context": "bd41d878bfa7a9112af639fbd56dc8de",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-serv",
        "start": 1795699631.412276,
        "end": 1795699631.412282,
        "events": {
          "name": "tls::sign",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  },
  {
    "context": "a1eb974b9a488489f9c735085092b38a",
    "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
    "executable": "gnutls-cli",
    "start": 1795699634.288516,
    "end": 1795699634.290282,
    "events": {
      "name": "tls::handshake",
      "tls::ciphersuite": 49200,
      "tls::protocol_version": 771,
      "tls::role": "client"
    },
    "spans": [
      {
        "context": "0ae36c5a2d6b48e6e23579999f9b6058",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-cli",
        "start": 1795699634.288699,
        "end": 1795699634.289111,
        "events": {
          "name": "tls::key_exchange",
          "tls::group": 29
        }
      },
      {
        "context": "b2a86f9a405af0121673ebf9198344df",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-cli",
        "start": 1795699634.290062,
        "end": 1795699634.290068,
        "events": {
          "name": "tls::verify",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  },
  {
    "context": "31720ee831cbddff777b5834b3218053",
    "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
    "executable": "gnutls-serv",
    "start": 1795699634.2904,
    "end": 1795699634.292166,
    "events": {
      "name": "tls::handshake",
      "tls::ciphersuite": 49200,
      "tls::protocol_version": 771,
      "tls::role": "server"
    },
    "spans": [
      {
        "context": "2e447e8567b59af193a5171aacb14ab9",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-serv",
        "start": 1795699634.290583,
        "end": 1795699634.290995,
        "events": {
          "name": "tls::key_exchange",
          "tls::group": 29
        }
      },
      {
        "context": "dd44b7c754d9648e5a095679bd6539a6",
        "origin": "5e2f1c8a9b7d4e3f60a1b2c3d4e5f60718293a4b",
        "executable": "gnutls-serv",
        "start": 1795699634.291946,
        "end": 1795699634.291952,
        "events": {
          "name": "tls::sign",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  }
]
```

From this output, a flamegraph can be generated with
`scripts/flamegraph.py`:

```console
$ crau-query | python scripts/flamegraph.py -
dumping data to flamegraph.html
```

You can then open the generated `flamegraph.html` in your browser.

## License

- `agent/src/bpf/audit.bpf.c`: GPL-2.0-or-later
- `dist/crau/*`: MIT OR Unlicense
- `scripts/flamegraph.py`: GPL-2.0-only
- everything else: GPL-3.0-or-later

## Credits

- [libbpf-async](https://github.com/fujita/libbpf-async) for the asynchronous BPF ring buffer implementation on top of libbpf-rs
- [rust-keylime](https://github.com/keylime/rust-keylime/) for the permission management code
