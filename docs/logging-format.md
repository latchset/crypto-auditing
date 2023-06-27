# Logging format for primary event logs

## Summary

This document specifies the format for a crypto-auditing primary event
logs.

To meet the practical use-cases, the proposed format is designed to be
able to capture events at multiple abstraction levels: from
invocations of low-level cryptographic primitives to TLS session
establishment.

## Design details

### Goals

- Contextual format: the logging format should be able to represent
  both high-level and low-level events, grouped by contexts
- Log truncation tolerance: the log file can be truncated at arbitrary
  record boundary

### Non-goals

- Human-readable format: there will be separate processes consuming
  the log format and converting it to application-specific
  representation

### Logging format

The general structure of the logging format is a stream of structured
event entries.

Events are classified into two categories: context mapping event and
data event.  The former maintains contexts associated with the latter.
The latter represents events themselves in a form of key-value pairs.

#### Example: TLS client handshake

A TLS handshake consists of several cryptographic operations, such as
digital-signature verification and key derivation.  For simplicity,
let's assume only digital-signature operations are involved.

There will be two contexts: an entire TLS handshake, and
digital-signature verification or creation, each of them is associated
to data events which describe the detail of those events, e.g., TLS
protocol version and digital-signature algorithm used.

Contexts are identified by unique 16-byte values, which are included
in any kind of events.  If the events were represented as a JSON
array, the log file would conceptually look like the following, though
a more efficient (binary) format will be used in practical deployment.

```json
[
    {
        "type": "new_context",
        "context": "00..01", // start of context 00..01
        "parent": "00..00"
    },
    {
        "type": "string_data",
        "context": "00..01",
        "name": "tls::handshake_client"
    },
    {
        "type": "word_data",
        "context": "00..01",
        "tls::protocol_version": 0x0304
    },
    {
        "type": "new_context",
        "context": "00..02", // start of context 00..02
        "parent": "00..01"
    },
    {
        "type": "string_data",
        "context": "00..02",
        "name": "tls::certificate_verify"
    },
    {
        "type": "word_data",
        "context": "00..02",
        "tls::signature_algorithm": 0x0804 // rsa_pss_rsae_sha256
    },
    {
        "type": "word_data",
        "context": "00..02",
        "pk::rsa_size": 3072
    }
]
```

This can be conceptually represented as a tree of events:

- `tls::handshake_client` (00..01)
  - `tls::protocol_version` = 0x0304
  - `tls::certificate_verify` (00..02)
    - `tls::signature_algorithm` = 0x0804
    - `pk::rsa_size` = 3072

Since the agent can monitor multiple processes, event sequences could
be interleaved with each other.  In that situation, context IDs help
to recover the original event sequences.

#### Context ID construction

For security and privacy reasons, context ID should be constructed to
be indistinguishable from the internal state of target programs, e.g.,
PID or memory address, while those information could be used as an
input to the construction algorithm. The recommended way of
constructing context ID as follows:

- The agent initializes an encryption key used with AES-ECB at startup
- An 8-byte context ID and an 8-byte PID/TGID of the target program
  are concatenated to construct a 16-byte input (i.e., a single block
  of AES-ECB)
- Encrypt the 16-byte input with AES-ECB using the key created above

This is inspired by the similar mechanism to [record number
encryption][rn-enc] in QUIC and DTLS 1.3 protocols.  With the AES-NI
instruction set enabled, this procedure consumes up to 15 cycles.

The agent may periodically rotate the key.

#### Event sequence compression based on context

When multiple events are sent within a single context, the same
context IDs are written into the log file, which could unnecessarily
consume disk space. Therefore, the log format supports compression of
subsequent events that share the same context ID, given a certain time
window.  With the compression enabled, the above example would look
like the following, preserving the same semantics:

```json
[
    {
        "context": "00..01", // start of context 00..01
        "events": [
            {
                "type": "new_context",
                "parent": "00..00"
            },
            {
                "type": "string_data",
                "name": "tls::handshake_client"
            },
            {
                "type": "word_data",
                "tls::protocol_version": 0x0304
            }
        ]
    },
    {
        "context": "00..02", // start of context 00..02
        "events": [
            {
                "type": "new_context",
                "parent": "00..01"
            },
            {
                "type": "string_data",
                "name": "tls::certificate_verify"
            },
            {
                "type": "word_data",
                "tls::signature_algorithm": 0x0804 // rsa_pss_rsae_sha256
            },
            {
                "type": "word_data",
                "pk::rsa_size": 3072
            }
        ]
    }
]
```

### Naming of event keys

While the keys can be arbitrary, this section provides a guidance on
how to construct them.  There are two types of keys: generic keys and
scoped keys.  Generic keys consists of only alphanumeric characters
and an underscore, while scoped keys can have a prefix ending with
"::".  In the previous example, `name` is a generic key, while
`tls::protocol_version` is a scoped key.  More strictly, they are
written in ABNF as follows:

```text
name = ALPHA *(ALPHA / DIGIT / "_")

generic_key = name
scoped_key = name "::" name
```

Keys are also used to determine value types.  For example, `name` can
take a string value, while `tls::protocol_version` takes a 16-bit
integer that corresponds to [`ProtocolVersion`][protocol-version]
(i.e., a 16-bit integer) in TLS.

The registry of those key names should be maintained in a separate
document.  The following section defines a few generic probe points
and TLS probe points.

#### Event keys registry

##### Generic keys

| key    | value type | description                                                     |
|--------|------------|-----------------------------------------------------------------|
| `name` | string     | the name of current context (available names are defined below) |

##### TLS context names

| name                      | description                                                      |
|---------------------------|------------------------------------------------------------------|
| `tls::handshake_client`   | TLS handshake for client                                         |
| `tls::handshake_server`   | TLS handshake for server                                         |
| `tls::certificate_sign`   | Digital signature is created using certificate in TLS handshake  |
| `tls::certificate_verify` | Digital signature is verified using certificate in TLS handshake |
| `tls::key_exchange`       | Shared secret derivation in TLS handshake                        |

##### TLS keys

| key                           | value type | description                                                                                      |
|-------------------------------|------------|--------------------------------------------------------------------------------------------------|
| `tls::protocol_version`       | uint16     | Negotiated TLS version                                                                           |
| `tls::ciphersuite`            | uint16     | Negotiated ciphersuite (as in IANA [registry][iana-tls-ciphersuites])                            |
| `tls::signature_algorithm`    | uint16     | Signature algorithm used in the handshake (as in IANA [registry][iana-tls-signature-algorithms]) |
| `tls::key_exchange_algorithm` | uint16     | Key exchange mode: ECDHE(0), DHE(1), PSK(2), ECDHE-PSK(3), DHE-PSK(4)                            |
| `tls::group`                  | uint16     | Groups used in the handshake (as in IANA [registry][iana-tls-supported-groups])                  |

##### SSH context names

| name                   | description                 |
|------------------------|-----------------------------|
| `ssh::handshake_client`| SSH handshake for client    |
| `ssh::handshake_server`| SSH handshake for server    |
| `ssh::client_key_sign` | SSH client key proof        |
| `ssh::server_key_sign` | SSH server key proof        |
| `ssh::key_exchange`    | SSH key exchange            |

##### SSH keys

All the keys except `rsa_bits` have `string` type.

| key                             | description                                      | example                                                     |
|---------------------------------|--------------------------------------------------|-------------------------------------------------------------|
| `ssh::ident_string`             | Software identity string                         | `SSH-2.0-OpenSSH_8.8`                                       |
| `ssh::key_algorithm`            | Key used in handshake                            | `ssh-ed25519`                                               |
| `ssh::rsa_bits`                 | Key bits (RSA only)                              | 2048                                                        |
| `ssh::cert_signature_algorithm` | If cert is used, signature algorithm of the cert | `ecdsa-sha2-nistp521`                                       |
| `ssh::kex_algorithm`            | Negotiated key exchange algorithm                | `curve25519-sha256`                                         |
| `ssh::kex_group`                | Group used for key exchange                      | For DH from moduli - modulus itself. Otherwise group name.  |
| `ssh::c2s_cipher`               | Data cipher algorithm                            | `aes256-gcm@openssh.com`                                    |
| `ssh::s2c_cipher`               |                                                  |                                                             |
| `ssh::c2s_mac`                  | Data integrity algorithm                         | empty string for "implicit"                                 |
| `ssh::s2c_mac`                  |                                                  |                                                             |
| `ssh::c2s_compression`          | Data compression algorithm                       | empty string for "none"                                     |
| `ssh::s2c_compression`          |                                                  |                                                             |

### CBOR based logging format definition

The recommended format of storing events is to use a sequence of
[CBOR] (Concise Binary Object Representation) objects.  The following
is the formal definition in [CDDL] (Concise Data Definition Language):

```text
LogEntry = EventGroup

EventGroup = {
  context: ContextID
  start: time
  end: time
  events: [+ Event]
}

Event = NewContext / Data

ContextID = bstr .size 16

NewContext = {
  NewContext: {
    parent: ContextID
  }
}

Data = {
  Data: {
    key: tstr
    value: uint .size 8 / tstr / bstr
  }
}
```

The log consists of a series of `EventGroup` objects, which groups
events in given time window from `start` to `end`.  Timestamps are
represented as a monotonic duration from the kernel boot time.
`ContextID` is an encrypted 16-byte context.

### Drawbacks and alternatives

### Questions

* How are algorithm identifiers represented in the log format and the
  protocol? String representation would require memory allocation at
  the BPF level, which might not be ideal. Integer representation
  would impose translation to the consumer components in the later
  pipeline. In both cases we need a registry to standardize known
  algorithm identifiers.

### Prior art

- Distributed tracing in microservices is a pattern that makes it easy to track end-to-end requests, by associating contexts to durations ("spans") of each service processing the requests ([explainer blog article](https://signoz.io/blog/distributed-tracing/), [another blog article](https://www.datadoghq.com/knowledge-center/distributed-tracing/))
- [KEP-3077: contextual logging](https://github.com/kubernetes/enhancements/tree/master/keps/sig-instrumentation/3077-contextual-logging) is a proposal to add contextual logging to Kubernetes, by allowing the context to be swapped
- [The SSLKEYLOGFILE Format](https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html#section-3) which uses 32 byte value of the Random field from the ClientHello message to distinguish TLS connections

[CBOR]: https://www.rfc-editor.org/rfc/rfc7049
[CDDL]: https://www.rfc-editor.org/rfc/rfc8610
[iana-tls-ciphersuites]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
[iana-tls-signature-algorithms]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
[iana-tls-supported-groups]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
[rn-enc]: https://www.rfc-editor.org/rfc/rfc9147.html#name-record-number-encryption
