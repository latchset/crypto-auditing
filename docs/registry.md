# Event keys registry

This document defines the registry of event key names used throughout
the crypto-auditing system. The following sections define generic probe
points as well as protocol-specific probe points for TLS and SSH.

## Presentation language

A protocol is typically defined with a context hierarchy, which can be
defined using the following presentation syntax.

### Miscellaneous

Comments begin with `"/*"` and end with `"*/"`.

### Scope

A scope groups multiple related events within a namespace. It is
defined using `scope <name> { ... }`, where `<name>` is the scope name.
The body of this block may contain context events or data events.

### Data events

A data event is defined using `<name>: <type>;`, where `<name>` is the
name of the data event and `<type>` is its data type. For example:

```
s1: string;
```

Available types are defined as follows:

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

### Context events

A context event is defined using a `context <name> { ... }` block,
where `<name>` is the name of the context event. The body of this block
may contain data events or other context events.

For example, 

```
context c1 {
  s1: string;
  context c2 {
    u1: uint16;
	context c3 {
	  i1: int16;
	}
  }
}
```

The hierarchy of context events must be preserved within the same scope.
In the example above, `c2` cannot appear at the top level, and `c3`
cannot be placed directly under `c1`.

However, context events from different scopes can be nested together.
For example, `pk::derive` (defined below) may appear within
`tls::key_exchange`.

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
  context sign {
    algorithm: string;
	curve: string;
	bits: uint16;
	hash: string;
  }

  context verify {
    algorithm: string;
	curve: string;
	bits: uint16;
	hash: string;
  }

  context encrypt {
    algorithm: string;
	bits: uint16;
	hash: string;
  }

  context decrypt {
    algorithm: string;
	bits: uint16;
	hash: string;
  }

  context encapsulate {
    algorithm: string;
  }

  context decapsulate {
    algorithm: string;
  }

  context generate {
    algorithm: string;
	bits: uint16;
  }

  context derive {
    algorithm: string;
	curve: string;
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

| key             | value type | description                                                                                                                |
|-----------------|------------|----------------------------------------------------------------------------------------------------------------------------|
| `pk::algorithm` | string     | Used algorithm name                                                                                                        |
| `pk::curve`     | string     | Elliptic curve name                                                                                                        |
| `pk::group`     | string     | FFDH group name                                                                                                            |
| `pk::bits`      | uint16     | Key strength in bits                                                                                                       |
| `pk::hash`      | string     | Hash algorithm used for signing or encryption (for prehashed or parametrized schemes such as ECDSA, RSA-PSS, and RSA-OAEP) |
| `pk::static`    | bool       | Whether `pk::derive` takes place with reused keys                                                                          |

## TLS

Events for TLS (Transport Layer Security) are scoped with `tls` and
defined as follows:

```
scope tls {
  context handshake {
    role: string;
	protocol_version: uint16;
	ciphersuite: uint16;

	context sign {
	  signature_algorithm: uint16;
	}

	context verify {
	  signature_algorithm: uint16;
	}

	context key_exchange {
	  group: uint16;
	}

	extended_master_secret: bool;
  }
}
```

### TLS context events

| name                | description                                                      |
|---------------------|------------------------------------------------------------------|
| `tls::handshake`    | TLS handshake                                                    |
| `tls::sign`         | Digital signature is created using certificate in TLS handshake  |
| `tls::verify`       | Digital signature is verified using certificate in TLS handshake |
| `tls::key_exchange` | Shared secret derivation in TLS handshake                        |

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
