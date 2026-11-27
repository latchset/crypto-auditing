# Logging format for primary event logs

## Summary

This document specifies the format of the crypto-auditing primary
event logs.

To support practical use cases, the format is designed to capture
events at multiple levels of abstraction: from invocations of
low-level cryptographic primitives to TLS session establishment.

## Design details

### Goals

- The format can convey contextual information. It represents not
  only individual cryptographic events (e.g., RSA signing), but also
  their context (e.g., the purpose they serve, such as TLS).
- The format can be stored in a compact form, such as the CBOR packed
  format, to eliminate repetition.
- The format tolerates basic modifications; for example, log files can
  be truncated at any record boundary.

### Overall structure

Events fall into two categories: data events and context events. Data
events carry the actual information as typed key-value pairs, while
context events maintain the contexts with which data events are
associated.

Each context is identified by a unique 16-byte value called a context
ID, which is included in every event.

Since the crypto-auditing agent monitors multiple processes, event
sequences from different sources may be interleaved. Context IDs make
it possible to regroup interleaved events into per-context sequences.

In addition to a context ID, a valid context must have a `name` data
event, as described in the event key [registry](registry.md).

Once a context is no longer in use, a `release_context` event may be
emitted with its context ID. After that, the context ID may be reused
for a different context, which starts with a new `new_context` event;
any other events with that context ID in between are ignored.

### Example: TLS client handshake

A TLS handshake involves several cryptographic operations, such as
digital signature verification and key derivation. For simplicity,
assume that only digital signature operations are involved.

In this case, there are two contexts: one for the entire TLS
handshake, and another for the digital signature verification (or
creation). Each context is associated with data events that describe
its details, such as the TLS protocol version and the digital
signature algorithm used.

At a high level, a TLS client handshake is therefore represented as
the following tree:

- `tls::handshake` (00..01)
  - `tls::role` = "client"
  - `tls::protocol_version` = 0x0304
  - `tls::verify` (00..02)
    - `tls::signature_algorithm` = 0x0804
    - `pk::bits` = 3072

At a low level, it is represented as a stream of structured event
entries. If the log file were represented as a JSON array, it would
conceptually look like the following, although a more efficient
binary format is used in practice.

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
        "name": "tls::handshake"
    },
    {
        "type": "string_data",
        "context": "00..01",
        "tls::role": "client"
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
        "name": "tls::verify"
    },
    {
        "type": "word_data",
        "context": "00..02",
        "tls::signature_algorithm": 0x0804 // rsa_pss_rsae_sha256
    },
    {
        "type": "word_data",
        "context": "00..02",
        "pk::bits": 3072,
    }
]
```

### Guidance on defining events

This section provides guidance on designing and organizing events for
a new protocol.

#### Event keys

Within a given context, event keys are unique. A key consists of
letters, digits, and underscores, and starts with a letter. It may
optionally be prefixed with a scope followed by "::", which represents
a protocol namespace such as TLS.

Formally, the syntax is defined in ABNF as follows:

```text
nchars = ALPHA *(ALPHA / DIGIT / "_")

key = [nchars "::"] nchars
```

#### Event values

A data event carries a value that is either a NUL-terminated string,
an integer that fits in a machine word, or an arbitrary blob of a
specified length.

For example, `name` takes a string value, while
`tls::protocol_version` takes an integer corresponding to the TLS
[`ProtocolVersion`][protocol-version] value.

For values that have no integer code assigned by the protocol
standards, it is recommended to use a string instead of inventing
synthetic integer values.

Although a boolean value could be represented by whether or not a data
event is emitted, it is recommended to explicitly emit an integer data
event with the value 0 or 1. This allows consumers to determine the
value immediately, even when event sequence compression (described
below) is enabled.

#### Context ID construction

For security and privacy reasons, context IDs should be constructed so
that they do not reveal the internal state of the target programs,
such as PIDs or memory addresses, although such information may be
used as input to the construction. The recommended construction is as
follows:

- At startup, the agent generates an encryption key for AES-ECB
- The 8-byte context value supplied by the probe and the 8-byte
  PID/TGID of the target program are concatenated to form a 16-byte
  input (i.e., a single AES block)
- The 16-byte input is encrypted with AES-ECB using that key

This is inspired by a similar mechanism for [record number
encryption][rn-enc] in QUIC and DTLS 1.3. With the AES-NI instruction
set, this procedure takes up to 15 cycles.

The agent may rotate the key periodically.

#### Event sequence compression based on context

When multiple events are emitted within a single context, the same
context ID is written to the log file repeatedly, which wastes disk
space. The log format therefore supports grouping consecutive events
that share the same context ID within a given time window. With this
compression, the example above looks like the following while
preserving the same semantics:

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
                "name": "tls::handshake"
            },
            {
                "type": "string_data",
                "tls::role": "client"
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
                "name": "tls::verify"
            },
            {
                "type": "word_data",
                "tls::signature_algorithm": 0x0804 // rsa_pss_rsae_sha256
            },
            {
                "type": "word_data",
                "pk::bits": 3072
            }
        ]
    }
]
```

### Mapping to CBOR

The recommended storage format for events is a sequence of [CBOR]
(Concise Binary Object Representation) objects. The formal definition
in [CDDL] (Concise Data Definition Language) is as follows:

```text
LogEntry = EventGroup

EventGroup = {
  context: ContextId
  start: time
  end: time
  events: [+ Event]
}

Event = NewContext / Data / ReleaseContext

ContextId = bstr .size 16

NewContext = {
  NewContext: {
    parent: ContextId
  }
}

ReleaseContext = {
  ReleaseContext: {}
}

Data = {
  Data: {
    key: tstr
    value: uint .size 8 / tstr / bstr
  }
}
```

The log consists of a series of `EventGroup` objects, each of which
groups the events that occurred within the time window from `start`
to `end`. Timestamps are represented as monotonic durations since
kernel boot. `ContextId` is the encrypted 16-byte context identifier.

The first `EventGroup` may be a virtual metadata group with an
all-zero `ContextId`, which carries information about the environment
as event entries. The following keys are currently defined:

| key         | value type | description                                  |
|-------------|------------|----------------------------------------------|
| `version`   | word       | the file format version (currently 1)        |
| `boot_time` | word       | kernel boot time in seconds since Unix epoch |

[CBOR]: https://www.rfc-editor.org/rfc/rfc8949
[CDDL]: https://www.rfc-editor.org/rfc/rfc8610
[protocol-version]: https://www.rfc-editor.org/info/rfc8446/#appendix-D.1
[rn-enc]: https://www.rfc-editor.org/rfc/rfc9147.html#name-record-number-encryption
