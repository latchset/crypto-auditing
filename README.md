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
    "context": "66cbb84ee07b90427845ee3d1ae087ba",
    "events": {
      "name": "tls::handshake_client",
      "tls::ciphersuite": 4866,
      "tls::protocol_version": 772
    },
    "map": [
      [
        "cc337d853f445ad282f4f2a0aec310d8",
        {
          "context": "cc337d853f445ad282f4f2a0aec310d8",
          "events": {
            "name": "tls::certificate_verify",
            "tls::signature_algorithm": 2057
          }
        }
      ]
    ]
  },
  {
    "context": "2b87eeaf728e24e17ddb8de38d9a7925",
    "events": {
      "name": "tls::handshake_server",
      "tls::ciphersuite": 4866,
      "tls::protocol_version": 772
    },
    "map": [
      [
        "33650fafec0364c22fa284cbe9c5b809",
        {
          "context": "33650fafec0364c22fa284cbe9c5b809",
          "events": {
            "name": "tls::certificate_verify",
            "tls::signature_algorithm": 2057
          }
        }
      ]
    ]
  },
  {
    "context": "56ef62bf96e87513e789538e9b880826",
    "events": {
      "name": "tls::handshake_client",
      "tls::ciphersuite": 49200,
      "tls::protocol_version": 771
    },
    "map": [
      [
        "7bcae3d1a6058293dd634220b266827f",
        {
          "context": "7bcae3d1a6058293dd634220b266827f",
          "events": {
            "name": "tls::certificate_verify",
            "tls::signature_algorithm": 2057
          }
        }
      ]
    ]
  },
  {
    "context": "2b87eeaf728e24e17ddb8de38d9a7925",
    "events": {
      "name": "tls::handshake_server",
      "tls::ciphersuite": 49200,
      "tls::protocol_version": 771
    },
    "map": [
      [
        "0c6044428c70bc8678c5035d9a2eed37",
        {
          "context": "0c6044428c70bc8678c5035d9a2eed37",
          "events": {
            "name": "tls::certificate_verify",
            "tls::signature_algorithm": 2057
          }
        }
      ]
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
- everything else: GPL-3.0-or-later

## Credits

- [libbpf-async](https://github.com/fujita/libbpf-async) for asynchronous BPF ringbuf implementation over libbpf-rs
- [rust-keylime](https://github.com/keylime/rust-keylime/) for permissions management code
