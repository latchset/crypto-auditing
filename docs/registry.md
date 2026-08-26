# Event keys registry

This document defines the registry of event key names used throughout
the crypto-auditing system. The following sections define generic probe
points as well as protocol-specific probe points for TLS and SSH.

## Presentation language

Tracing metadata across supported protocols follows a hierarchical
model consisting of contexts and leaf data events. This section
defines the formal syntax used to describe this structured hierarchy.

### Miscellaneous

Comments follow C-style block syntax. They begin with `/*` and
terminate with `*/`. Comments do not nest and carry no semantic value.

### Scope

A scope establishes an explicit namespace to logically group related
protocol events.

*Syntax:*

```
scope <name> {
  /* scope declarations */
}
```

where `<name>` is an identifier representing the namespace, and the
enclosed block accepts one or more event declarations.

### Event categories

The schema distinguishes between two event types: Data Events and
Context Events.

Implementation Note: All defined events are optional within emitted
traces. Consuming applications must handle omitted fields gracefully
and not assume event presence.

#### Data events

Data events represent leaf key-value pairs assigned to a context.

*Syntax:*

```
<name>: <type>;
```

where `<name>` is the identifier of the data event and `<type>` is the data type of the value.

##### Supported data types

| type   | representation | description                       |
|--------|----------------|-----------------------------------|
| string | string         | a NUL-terminated string           |
| blob   | blob           | a binary blob                     |
| bool   | word           | boolean (0 for false, 1 for true) |
| uint8  | word           | 8-bit unsigned integer            |
| uint16 | word           | 16-bit unsigned integer           |
| uint32 | word           | 32-bit unsigned integer           |
| uint64 | word           | 64-bit unsigned integer           |
| int8   | word           | 8-bit signed integer              |
| int16  | word           | 16-bit signed integer             |
| int32  | word           | 32-bit signed integer             |
| int64  | word           | 64-bit signed integer             |

#### Context events

Context events establish structural nodes within the event tree using
the `context` keyword.

*Syntax:*

```
context <name1>[, <name2>...] {
  /* child data, context events, or allowed_children rules */
}
```

A context declaration accepts either a single name or a
comma-separated list of names that share identical block contents. The
enclosed block may contain data events or child context events,
allowing arbitrary nesting.

##### Nesting rules

The context hierarchy defined in the schema is invariant within a
given scope. A child context cannot be moved to the root level or
attached to an undeclared parent context.

*Example:*

```
context c1 {
  s1: string;
  context c2 {
    u1: uint16;
    context c3, c4 {
      i1: int16;
    }
  }
}
```

In this structure, the outermost context `c1` contains scalar `s1` and
nested context `c2`. Context `c2` contains scalar `u1` alongside
context events `c3` and `c4`, both of which enclose data event
`i1`. Runtime events must preserve this precise hierarchy; `c2` cannot
appear at the top level, nor can `c3` be placed directly beneath `c1`.

##### The `allowed_children` directive

By default, only explicitly declared inline child contexts may appear
under a parent context. To allow external top-level context events as
valid runtime children, a context must declare an `allowed_children`
directive.

This directive takes a comma-separated list of pattern declarations
using the syntax `allowed_children <pattern1>[, <pattern2>, ...];`. A
pattern can specify an explicit context name in the current scope
(`<context_name>`), an explicit context in an external scope
(`<scope_name>::<context_name>`), or a wildcard matching all top-level
contexts in a given scope (`<scope_name>::*`). If the scope prefix is
omitted, the current scope is assumed.

For example:

```
scope this {
  context c1 {
    s1: string;
    context c2 {
      u1: uint16;
      allowed_children c1, other::*;
    }
  }
}
```

Here, context `c2` explicitly permits either `this::c1` or any
top-level context defined within the other scope to appear as valid
runtime children.

## Generic data events

The following are generic data events that can be associated with any
context:

| key    | value type | description                                                     |
|--------|------------|-----------------------------------------------------------------|
| `name` | string     | the name of the current context (available names are defined below) |

## Public key cryptography

Events for generic public key cryptography are scoped with `pk` and
defined as follows:

```
scope pk {
  context sign, verify {
    algorithm: string;
    curve: string;
    bits: uint16;
    hash: string;
    rsa_padding: string;
  }

  context encrypt, decrypt {
    algorithm: string;
    bits: uint16;
    hash: string;
    rsa_padding: string;
  }

  context encapsulate {
    algorithm: string;
    allowed_children derive, encapsulate; /* for hybrid construction */
  }

  context decapsulate {
    algorithm: string;
    allowed_children derive, decapsulate; /* for hybrid construction */
  }

  context generate {
    algorithm: string;
    curve: string;
    group: string;
    bits: uint16;
  }

  context derive {
    algorithm: string;
    curve: string;
    group: string;
    bits: uint16;
    static: bool;
  }
}
```

### Public key cryptography context events

| name              | description                     |
|-------------------|---------------------------------|
| `pk::sign`        | A digital signature is created  |
| `pk::verify`      | A digital signature is verified |
| `pk::encrypt`     | Encryption is performed         |
| `pk::decrypt`     | Decryption is performed         |
| `pk::encapsulate` | A session key is encapsulated   |
| `pk::decapsulate` | A session key is decapsulated   |
| `pk::generate`    | A private key is generated      |
| `pk::derive`      | A shared secret is generated    |

### Public key cryptography data events

| key               | value type | description                                                                                                                |
|-------------------|------------|----------------------------------------------------------------------------------------------------------------------------|
| `pk::algorithm`   | string     | Used algorithm name                                                                                                        |
| `pk::curve`       | string     | Elliptic curve name                                                                                                        |
| `pk::group`       | string     | FFDH group name                                                                                                            |
| `pk::bits`        | uint16     | Key strength in bits                                                                                                       |
| `pk::hash`        | string     | Hash algorithm used for signing or encryption (for prehashed or parametrized schemes such as ECDSA, RSA-PSS, and RSA-OAEP) |
| `pk::rsa_padding` | string     | Padding mode used for signing or encryption in RSA. While this can be an arbitrary string, the following values are pre-defined: "pss" for RSA-PSS, "oaep" for RSA-OAEP, and "pkcs1-v1.5" for PKCS#1 v1.5 |
| `pk::static`      | bool       | Whether `pk::derive` takes place with reused keys                                                                          |

## TLS

Events for TLS (Transport Layer Security) are scoped with `tls` and
defined as follows:

```
scope tls {
  context handshake {
    role: string;
    protocol_version: uint16;
    ciphersuite: uint16;

    context key_exchange {
      group: uint16;
      allowed_children pk::generate, pk::derive, pk::encapsulate, pk::decapsulate;
    }

    context sign, verify {
      signature_algorithm: uint16;
      allowed_children pk::sign, pk::verify;
    }

    context verify_cert_chain {
      allowed_children pk::verify;
    }

    extended_master_secret: bool;
  }
}
```

### TLS context events

| name                     | description                                                                             |
|--------------------------|-----------------------------------------------------------------------------------------|
| `tls::handshake`         | A TLS handshake is in progress                                                          |
| `tls::key_exchange`      | A shared secret is derived in TLS handshake                                             |
| `tls::sign`              | A TLS handshake message (e.g., CertificateVerify in TLS 1.3) is digitally signed        |
| `tls::verify`            | A signature on a TLS handshake message (e.g., CertificateVerify in TLS 1.3) is verified |
| `tls::verify_cert_chain` | A certificate chain presented during a TLS handshake is verified                        |

### TLS data events

| name                          | type   | description                                                                                      |
|-------------------------------|--------|--------------------------------------------------------------------------------------------------|
| `tls::role`                   | string | The role of a peer ("client" or "server")                                                        |
| `tls::protocol_version`       | uint16 | Negotiated TLS version                                                                           |
| `tls::ciphersuite`            | uint16 | Negotiated ciphersuite (as in IANA [registry][iana-tls-ciphersuites])                            |
| `tls::signature_algorithm`    | uint16 | Signature algorithm used in the handshake (as in IANA [registry][iana-tls-signature-algorithms]) |
| `tls::group`                  | uint16 | Groups used in the handshake (as in IANA [registry][iana-tls-supported-groups])                  |
| `tls::extended_master_secret` | bool   | Whether extended_master_secret extension is negotiated                                           |

## SSH

Note: This section is not finalized yet.

Events for SSH (Secure SHell) are scoped with `ssh` and defined as
follows:

```
scope ssh {
  context handshake {
    role: string;
    ident_string: string;
    peer_ident_string: string;
    context key_exchange {
      kex_algorithm: string;
      kex_group: string;
      key_algorithm: string;
      c2s_cipher: string;
      s2c_cipher: string;
      c2s_mac: string;
      s2c_mac: string;
      c2s_compression: string;
      s2c_compression: string;
    }

    context client_key {
      key_algorithm: string;
      cert_signature_algorithm: string;
      rsa_bits: uint16;
    }

    context server_key {
      key_algorithm: string;
      cert_signature_algorithm: string;
      rsa_bits: uint16;
    }
  }
}
```

### SSH context events

| name                    | description                           |
|-------------------------|---------------------------------------|
| `ssh::handshake`        | SSH handshake                         |
| `ssh::client_key`       | SSH client key signature/verification |
| `ssh::server_key`       | SSH server key signature/verification |
| `ssh::key_exchange`     | SSH key exchange                      |

### SSH data events

All keys except `rsa_bits` have `string` type.
Server and client values are distinguished by their context. All relevant events are logged in both contexts.

| name                            | type   | description                                                                     |
|---------------------------------|--------|---------------------------------------------------------------------------------|
| `ssh::role`                     | string | The role of a peer ("client" or "server")                                       |
| `ssh::ident_string`             | string | Software identification string, such as `SSH-2.0-OpenSSH_8.8`                   |
| `ssh::peer_ident_string`        | string | Peer software identification string, such as `SSH-2.0-OpenSSH_8.8`              |
| `ssh::key_algorithm`            | string | Key used in handshake/key ownership proof, such as `ssh-ed25519`                |
| `ssh::rsa_bits`                 | uint16 | Key bits (RSA only)                                                             |
| `ssh::cert_signature_algorithm` | string | If cert is used, signature algorithm of the cert, such as `ecdsa-sha2-nistp521` |
| `ssh::kex_algorithm`            | string | Negotiated key exchange algorithm, such as `curve25519-sha256`                  |
| `ssh::kex_group`                | string | Group used for key exchange                                                     |
| `ssh::c2s_cipher`               | string | Data cipher algorithm, such as `aes256-gcm@openssh.com`                         |
| `ssh::s2c_cipher`               | string | Data cipher algorithm, such as `aes256-gcm@openssh.com`                         |
| `ssh::c2s_mac`                  | string | Data integrity algorithm, such as `umac-128-etm@openssh.com`                    |
| `ssh::s2c_mac`                  | string | Data integrity algorithm, such as `umac-128-etm@openssh.com`                    |
| `ssh::c2s_compression`          | string | Data compression algorithm, such as `zlib@openssh.com`                          |
| `ssh::s2c_compression`          | string | Data compression algorithm, such as `zlib@openssh.com`                          |

[iana-tls-ciphersuites]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
[iana-tls-signature-algorithms]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
[iana-tls-supported-groups]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
[rn-enc]: https://www.rfc-editor.org/rfc/rfc9147.html#name-record-number-encryption
