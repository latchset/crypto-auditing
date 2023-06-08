# crypto-auditing

## Introduction

This project aims to create the infrastructure needed to audit crypto
operations performed by crypto libraries on a system. This is accomplished by
using BPF USDT probes to intercept specific entry points in crypto libraries,
as they are used by user space processes on the system, and collect data so that
it can be analyzed later.

The design documents can be found from the following links:

- [Objectives and high-level design](docs/objectives.md)
- [Architecture](docs/architecture.md)
- [Logging format for primary event logs](docs/logging-format.md)
- [USDT probe points](docs/probe-points.md)

## Compiling

1. Install the latest Rust toolchain
1. Install the dependencies (note that libbpf 1.1.1 or later is required)
```console
$ sudo dnf install bpftool make libbpf-devel llvm-devel rustfmt
```
1. Build the programs with `make`
```console
$ make
```

The first step requires `agent/src/bpf/vmlinux.h` to be populated. By
default it is done through BTF dump from the running kernel with
`bpftool`, but if it is not supported in your system, it is possible
to use `vmlinux.h` included in the `kernel-devel` package:

```console
$ sudo dnf install kernel-devel
$ cp $(rpm -ql kernel-devel | grep '/vmlinux.h$' | tail -1) agent/src/bpf
```

1. Install the programs with `make install` (optional)
```console
$ sudo make install
```

## Running

1. Compile the target crypto library with defined tracepoints are enabled
```console
$ git clone --depth=1 -b wip/usdt https://gitlab.com/gnutls/gnutls.git
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
```
2. Run the agent as root
```console
$ sudo ./target/debug/crypto-auditing-agent --library .../gnutls/lib/.libs/libgnutls.so.30.35.0
```
3. On another terminal, run any commands using the instrumented library
```console
$ ./src/gnutls-serv --x509certfile=doc/credentials/x509/cert-rsa-pss.pem --x509keyfile=doc/credentials/x509/key-rsa-pss.pem &
$ ./src/gnutls-cli --x509cafile=doc/credentials/x509/ca.pem localhost -p 5556
^C
$ ./src/gnutls-cli --x509cafile=doc/credentials/x509/ca.pem localhost -p 5556 --priority NORMAL:-VERS-TLS1.3
```

## Inspecting logs

By default, the log will be stored in `audit.cborseq` in a sequence of
CBOR objects, which can be parsed and printed as a tree with the
`log_parser` executable:
```console
$ cargo run --bin crypto-auditing-log-parser audit.cborseq
[
  {
    "context": "33acb8e6ccc65bb285bd2f84cac3bf80",
    "start": 49431626623324,
    "end": 49431626623324,
    "events": {
      "name": "tls::handshake_client",
      "tls::ciphersuite": 4866,
      "tls::protocol_version": 772
    },
    "spans": [
      {
        "context": "cdbaebffb957deffec8664b52ab8290d",
        "start": 49431631956782,
        "end": 49431631963209,
        "events": {
          "name": "tls::certificate_verify",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  },
  {
    "context": "c8e0a865bab48563e70780234c3de1c0",
    "start": 49431626833778,
    "end": 49431627033707,
    "events": {
      "name": "tls::handshake_server",
      "tls::ciphersuite": 4866,
      "tls::protocol_version": 772
    },
    "spans": [
      {
        "context": "3c062a160cc8bc8113d05eff4ffc5da5",
        "start": 49431628203429,
        "end": 49431628207396,
        "events": {
          "name": "tls::certificate_verify",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  },
  {
    "context": "953c66fdd64be71bf99ccc4b91298c95",
    "start": 49434502888728,
    "end": 49434502888728,
    "events": {
      "name": "tls::handshake_client",
      "tls::ciphersuite": 49200,
      "tls::protocol_version": 771
    },
    "spans": [
      {
        "context": "d5ba85329440a679aece93ef63322753",
        "start": 49434509684783,
        "end": 49434509694813,
        "events": {
          "name": "tls::certificate_verify",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  },
  {
    "context": "c8e0a865bab48563e70780234c3de1c0",
    "start": 49434503007039,
    "end": 49434503047270,
    "events": {
      "name": "tls::handshake_server",
      "tls::ciphersuite": 49200,
      "tls::protocol_version": 771
    },
    "spans": [
      {
        "context": "983d47ffeaf4b50691c80f2431c6b539",
        "start": 49434503929186,
        "end": 49434503940540,
        "events": {
          "name": "tls::certificate_verify",
          "tls::signature_algorithm": 2057
        }
      }
    ]
  }
]
```

To simply deserialize it, you can use the `cborseq2json.rb` script
from [cbor-diag](https://github.com/cabo/cbor-diag) package, which can
be installed with `gem install --user cbor-diag`.

## License

- `agent/src/bpf/audit.bpf.c`: GPL-2.0-or-later
- `agent/src/ringbuf.rs`: LGPL-2.1-only or BSD-2-Clause
- `dist/audit.h`: MIT
- `scripts/flamegraph.py`: GPL-2.0-only
- everything else: GPL-3.0-or-later

## Credits

- [libbpf-async](https://github.com/fujita/libbpf-async) for asynchronous BPF ringbuf implementation over libbpf-rs
- [rust-keylime](https://github.com/keylime/rust-keylime/) for permissions management code
- [tarpc](https://github.com/google/tarpc) for the pubsub example implementation
