# Event keys registry

This document defines the registry of event keys used throughout the
crypto-auditing system. The following sections define generic events
as well as events specific to public key cryptography, TLS, and SSH.

The schema language used here is described in a separate
[document](schema.md).

## Generic data events

The following generic data events can be associated with any context:

| key    | value type | description                                                              |
|--------|------------|--------------------------------------------------------------------------|
| `name` | string     | the name of the current context (the available names are defined below) |

## Public key cryptography

Events for generic public key cryptography are scoped under `pk` and
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

  context encapsulate, decapsulate {
    algorithm: string;
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
| `pk::encrypt`     | Data is encrypted               |
| `pk::decrypt`     | Data is decrypted               |
| `pk::encapsulate` | A shared secret is encapsulated |
| `pk::decapsulate` | A shared secret is decapsulated |
| `pk::generate`    | A key pair is generated         |
| `pk::derive`      | A shared secret is derived      |

### Public key cryptography data events

| key               | value type | description                                                                                                                                                                   |
|-------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pk::algorithm`   | string     | Algorithm name                                                                                                                                                                |
| `pk::curve`       | string     | Elliptic curve name                                                                                                                                                           |
| `pk::group`       | string     | FFDH group name                                                                                                                                                               |
| `pk::bits`        | uint16     | Key size in bits                                                                                                                                                              |
| `pk::hash`        | string     | Hash algorithm used for signing or encryption (for schemes that prehash the input or are parameterized by a hash, such as ECDSA, RSA-PSS, and RSA-OAEP)                       |
| `pk::rsa_padding` | string     | Padding scheme used for RSA signing or encryption. Although this can be an arbitrary string, the following values are predefined: "pss" for RSA-PSS, "oaep" for RSA-OAEP, and "pkcs1-v1.5" for PKCS #1 v1.5 |
| `pk::static`      | bool       | Whether `pk::derive` uses a static (reused) key                                                                                                                               |

## TLS

Events for TLS (Transport Layer Security) are scoped under `tls` and
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
| `tls::key_exchange`      | A shared secret is established during a TLS handshake                                   |
| `tls::sign`              | A TLS handshake message (e.g., CertificateVerify in TLS 1.3) is digitally signed        |
| `tls::verify`            | A signature on a TLS handshake message (e.g., CertificateVerify in TLS 1.3) is verified |
| `tls::verify_cert_chain` | A certificate chain presented during a TLS handshake is verified                        |

### TLS data events

| key                           | value type | description                                                                                                                       |
|-------------------------------|------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `tls::role`                   | string     | The role of the local endpoint ("client" or "server")                                                                             |
| `tls::protocol_version`       | uint16     | Negotiated TLS version                                                                                                            |
| `tls::ciphersuite`            | uint16     | Negotiated cipher suite (as in the IANA [registry][iana-tls-ciphersuites])                                                        |
| `tls::signature_algorithm`    | uint16     | Signature algorithm used in the handshake (as in the IANA [registry][iana-tls-signature-algorithms])                              |
| `tls::group`                  | uint16     | Group used for key exchange (as in the IANA [registry][iana-tls-supported-groups]), or 0 if unknown (e.g., custom FFDHE parameters in TLS 1.2) |
| `tls::extended_master_secret` | bool       | Whether the extended_master_secret extension is negotiated                                                                        |

## SSH

Note: this section has not been finalized yet.

Events for SSH (Secure Shell) are scoped under `ssh` and defined as
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

| name                | description                                            |
|---------------------|--------------------------------------------------------|
| `ssh::handshake`    | An SSH handshake is in progress                        |
| `ssh::client_key`   | A signature with the client key is created or verified |
| `ssh::server_key`   | A signature with the server key is created or verified |
| `ssh::key_exchange` | An SSH key exchange is performed                       |

### SSH data events

Client-side and server-side values are distinguished by the context in
which they appear. All relevant events are logged in both contexts.

| key                             | value type | description                                                                    |
|---------------------------------|------------|--------------------------------------------------------------------------------|
| `ssh::role`                     | string     | The role of the local endpoint ("client" or "server")                          |
| `ssh::ident_string`             | string     | Local software identification string, such as `SSH-2.0-OpenSSH_8.8`           |
| `ssh::peer_ident_string`        | string     | Peer software identification string, such as `SSH-2.0-OpenSSH_8.8`            |
| `ssh::key_algorithm`            | string     | Key algorithm used in the handshake or for proof of key ownership, such as `ssh-ed25519` |
| `ssh::rsa_bits`                 | uint16     | Key size in bits (RSA only)                                                    |
| `ssh::cert_signature_algorithm` | string     | Signature algorithm of the certificate, if one is used, such as `ecdsa-sha2-nistp521` |
| `ssh::kex_algorithm`            | string     | Negotiated key exchange algorithm, such as `curve25519-sha256`                 |
| `ssh::kex_group`                | string     | Group used for key exchange                                                    |
| `ssh::c2s_cipher`               | string     | Client-to-server cipher algorithm, such as `aes256-gcm@openssh.com`            |
| `ssh::s2c_cipher`               | string     | Server-to-client cipher algorithm, such as `aes256-gcm@openssh.com`            |
| `ssh::c2s_mac`                  | string     | Client-to-server MAC algorithm, such as `umac-128-etm@openssh.com`             |
| `ssh::s2c_mac`                  | string     | Server-to-client MAC algorithm, such as `umac-128-etm@openssh.com`             |
| `ssh::c2s_compression`          | string     | Client-to-server compression algorithm, such as `zlib@openssh.com`             |
| `ssh::s2c_compression`          | string     | Server-to-client compression algorithm, such as `zlib@openssh.com`             |

[iana-tls-ciphersuites]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
[iana-tls-signature-algorithms]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
[iana-tls-supported-groups]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
