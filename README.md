# crypto-auditing

## Introduction

This project aims to create the infrastructure needed to audit crypto
operations performed by crypto libraries on a system. This is accomplished by
using BPF USDT probes to intercept specific entry points in crypto libraries,
as they are used by user space processes on the system, and collect data so that
it can be analyzed later.

The primary use-case of this project is to facilitate the migration of
organizations to post-quantum cryptography. Since post-quantum
algorithms are relatively new and not all applications are immediately
compatible, mandatory switch from classical cryptography is
impractical. To enable a smoother transition, crypto-auditing can be
employed at run time to identify any instances where classical
cryptography is still in use.

The design documents can be found from the following links:

- [Objectives and high-level design](docs/objectives.md)
- [Architecture](docs/architecture.md)
- [Logging format for primary event logs](docs/logging-format.md)
- [USDT probe points](docs/probe-points.md)
- [Measuring performance impact](docs/performance.md)

## Installation

1. Install the latest Rust toolchain
2. Install the dependencies (note that libbpf 1.1.1 or later is required)
```console
$ sudo dnf install bpftool make libbpf-devel llvm-devel rustfmt
```
3. Build the programs with `make`
```console
$ make
```
4. Install the programs with `make install`
```console
$ sudo make install
```

## Running

1. Create dedicated user and group (e.g., crypto-auditing:crypto-auditing)
```console
$ sudo groupadd crypto-auditing
$ sudo useradd -g crypto-auditing
```
2. Modify systemd configuration for agent in `/lib/systemd/system/crau-agent.service`:
```ini
User=crypto-auditing
Group=crypto-auditing
```
3. Modify systemd configuration for event-broker in `/lib/systemd/system/crau-event-broker.socket`:
```ini
SocketUser=crypto-auditing
SocketGroup=crypto-auditing
SocketMode=0660
```
4. Modify agent configuration in `/etc/crypto-auditing/agent.conf`:
```toml
library = ["/path/to/installation/lib64/libgnutls.so.30"]
user = "crypto-auditing:crypto-auditing"
```
5. Enable agent
```console
$ sudo systemctl daemon-reload
$ sudo systemctl start crau-agent.service
```
6. Run monitor
```console
$ crau-monitor
```
7. On another terminal, run any commands using the instrumented library, such as GnuTLS in Fedora Linux 43 or later
```console
$ gnutls-serv --x509certfile=doc/credentials/x509/cert-rsa-pss.pem --x509keyfile=doc/credentials/x509/key-rsa-pss.pem &
$ gnutls-cli --x509cafile=doc/credentials/x509/ca.pem localhost -p 5556
^C
$ gnutls-cli --x509cafile=doc/credentials/x509/ca.pem localhost -p 5556 --priority NORMAL:-VERS-TLS1.3
```

## Inspecting logs

In the above example, client stores logs as a sequence of
CBOR objects, which can be parsed and printed as a tree with the
`crau-query` executable:
```console
$ crau-query --log-file audit.cborseq
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
          "name": "tls::verify",
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
          "name": "tls::verify",
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
          "name": "tls::verify",
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
          "name": "tls::verify",
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

From the tree output, a flamegraph can be produced with the
`scripts/flamegraph.py`:

```console
$ crau-query --log-file audit.cborseq | python scripts/flamegraph.py -
dumping data to flamegraph.html
```

You can open the generated `flamegraph.html` with your browser.

## License

- `agent/src/bpf/audit.bpf.c`: GPL-2.0-or-later
- `dist/crau/*`: MIT OR Unlicense
- `scripts/flamegraph.py`: GPL-2.0-only
- everything else: GPL-3.0-or-later

## Credits

- [libbpf-async](https://github.com/fujita/libbpf-async) for asynchronous BPF ringbuf implementation over libbpf-rs
- [rust-keylime](https://github.com/keylime/rust-keylime/) for permissions management code
