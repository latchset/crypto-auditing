# Logging format for primary event logs

## Summary

This document specifies the format for crypto-auditing primary event
logs.

To meet the practical use-cases, the proposed format is designed to be
able to capture events at multiple abstraction levels: from
invocations of low-level cryptographic primitives to TLS session
establishment.

## Design details

### Goals

- The format can convey contextual information. It can not only
  represents individual cryptographic events (e.g., RSA signing), but
  also provide the context (e.g., for which purpose it is used, such
  as TLS).
- The format can be represented in a compact form, such as CBOR packed
  format to eliminating repetition.
- The format provides basic tolerance of modification, e.g., the log
  files can be truncated at any record boundary.

### Overall structure

Events are classified into two categories: data events and context
events. Data events represent the events themselves as typed key-value
pairs. Context events maintain the contexts associated with data
events.

Contexts are identified by unique 16-byte values called context IDs,
which are included in all types of events.

Since the crypto-auditing agent monitor multiple processes, event
sequences may be interleaved with each other. Context IDs enable
reconstructing interleaved events into same context sequences.

### Example: TLS client handshake

A TLS handshake consists of several cryptographic operations, such as
digital signature verification and key derivation. For simplicity,
let's assume only digital signature operations are involved.

There will be two contexts: one for the entire TLS handshake, and
another for digital signature verification or creation. Each context is
associated with data events that describe the details of those events,
e.g., TLS protocol version and digital signature algorithm used.

Therefore, at a high level, a TLS client handshake is represented as
a tree as follows:

- `tls::handshake` (00..01)
  - `tls::role` = "client"
  - `tls::protocol_version` = 0x0304
  - `tls::verify` (00..02)
    - `tls::signature_algorithm` = 0x0804
    - `pk::bits` = 3072

At a low level, this is represented as a stream of structured event
entries.  If the log file is represented as a JSON array, it would
conceptually look like the following, though a more efficient (binary)
format is used in practice.

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

This section provides some guidance on designing and organizing the
events for a new protocol.

#### Naming of event keys

Event keys are named with alphanumeric characters and underscores,
with an optional scope prefix delimited by "::". More formally, they
are written in ABNF as follows:

```text
nchars = ALPHA *(ALPHA / DIGIT / "_")

key = [nchars "::"] nchars
```

Scopes are used to denote a protocol namespace, such as TLS.

#### Types of event values

A data event conveys a data item that is either a NUL-terminated string,
an integer that fits in a machine word, or an arbitrary blob with a
specified length.

For example, `name` takes a string value, while
`tls::protocol_version` takes an integer that corresponds to the
[`ProtocolVersion`][protocol-version] value in TLS.

For values that don't have an integral value assigned by the protocol
standards, it's recommended to use a string value instead of coming up
with synthetic integer ones.

While it is possible to represent a boolean value by choosing whether
or not to emit a data event, it is recommended to explicitly emit an
integer data event with value 0 or 1. This allows the application to
determine the value immediately, even when event sequence compression
(see below) is enabled.

#### Context ID construction

For security and privacy reasons, context IDs should be constructed to
not reveal internal state of target programs, such as PIDs or memory
addresses, although such information may be used as input to the
construction algorithm. The recommended way to construct a context ID
is as follows:

- The agent initializes an encryption key for AES-ECB at startup
- An 8-byte context ID and an 8-byte PID/TGID of the target program
  are concatenated to construct a 16-byte input (i.e., a single AES-ECB
  block)
- The 16-byte input is encrypted with AES-ECB using the key created above

This is inspired by a similar mechanism for [record number
encryption][rn-enc] in the QUIC and DTLS 1.3 protocols. With the AES-NI
instruction set enabled, this procedure takes up to 15 cycles.

The agent may periodically rotate the key.

#### Event sequence compression based on context

When multiple events are sent within a single context, the same
context IDs are written to the log file, which can unnecessarily
consume disk space. Therefore, the log format supports compression of
consecutive events that share the same context ID within a given time
window. With compression enabled, the above example would look like the
following while preserving the same semantics:

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
                "pk::rsa_size": 3072
            }
        ]
    }
]
```

### Mapping to CBOR

The recommended format for storing events is a sequence of
[CBOR] (Concise Binary Object Representation) objects. The following
is the formal definition in [CDDL] (Concise Data Definition Language):

```text
LogEntry = EventGroup

EventGroup = {
  context: ContextId
  start: time
  end: time
  events: [+ Event]
}

Event = NewContext / Data

ContextId = bstr .size 16

NewContext = {
  NewContext: {
    parent: ContextId
  }
}

Data = {
  Data: {
    key: tstr
    value: uint .size 8 / tstr / bstr
  }
}
```

The log consists of a series of `EventGroup` objects, each grouping
events within a given time window from `start` to `end`. Timestamps are
represented as monotonic durations from kernel boot time.
`ContextId` is an encrypted 16-byte context identifier.

The first `EventGroup` may be a virtual metadata group with an
all-zero `ContextId`. This is used to include environmental
information as event entries. The following events are currently
defined:

| key         | value type | description                                 |
|-------------|------------|---------------------------------------------|
| `version`   | word       | the file format version (should be 1)       |
| `boot_time` | word       | kernel boot time in seconds from Unix epoch |

[CBOR]: https://www.rfc-editor.org/rfc/rfc7049
[CDDL]: https://www.rfc-editor.org/rfc/rfc8610
[protocol-version]: https://www.rfc-editor.org/info/rfc8446/#appendix-D.1
[rn-enc]: https://www.rfc-editor.org/rfc/rfc9147.html#name-record-number-encryption
