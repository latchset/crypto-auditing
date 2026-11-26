// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

//! Event sequences mimicking what an instrumented TLS library emits
//! during TLS 1.3 handshakes.  They are not tied to any particular
//! library: context IDs, build IDs, timestamps, and algorithm names
//! are synthetic, while names and keys follow the built-in schema and
//! numeric identifiers follow the IANA TLS registries.

use crypto_auditing::trace::{Process, Result, Trace, Value::*};
use std::time::Duration;

/// Parent of a root context; any non-zero value which is not used as
/// a context ID
const NO_PARENT: i64 = -1;

/// Build ID of the instrumented library
const BUILD_ID: [u8; 20] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
];

/// TLS 1.3
const TLS13: i64 = 0x0304;
/// TLS_AES_256_GCM_SHA384
const TLS_AES_256_GCM_SHA384: i64 = 0x1302;
/// X25519MLKEM768
const X25519MLKEM768: i64 = 0x11ec;
/// secp256r1
const SECP256R1: i64 = 0x0017;
/// ed25519
const ED25519: i64 = 0x0807;

/// Context IDs used in a client handshake; they are typically
/// pointers to the objects on the heap or stack
struct ClientContexts {
    handshake: i64,
    key_exchange: i64,
    key_exchange2: i64,
    generate: [i64; 3],
    decapsulate: i64,
    derive: i64,
    verify: i64,
    verify_pk: i64,
    verify_cert_chain: i64,
    verify_cert: i64,
}

impl ClientContexts {
    fn new(heap: i64, stack: i64) -> Self {
        Self {
            handshake: heap,
            key_exchange: stack,
            key_exchange2: stack + 0x100,
            generate: [heap + 0x10, heap + 0x20, heap + 0x30],
            decapsulate: heap + 0x40,
            derive: heap + 0x50,
            verify: stack + 0x200,
            verify_pk: stack + 0x300,
            verify_cert_chain: stack + 0x400,
            verify_cert: stack + 0x500,
        }
    }
}

/// ClientHello offering two key shares: X25519MLKEM768 and secp256r1
fn client_hello(t: &mut Trace, p: &Process, c: &ClientContexts) -> Result<()> {
    t.span(
        p,
        c.handshake,
        NO_PARENT,
        "tls::handshake",
        &[("tls::role", String("client"))],
    )?;
    t.span(
        p,
        c.key_exchange,
        c.handshake,
        "tls::key_exchange",
        &[("tls::group", Word(X25519MLKEM768))],
    )?;
    for (generate, algorithm) in c.generate.iter().zip(["ML-KEM-768", "X25519"]) {
        t.span(
            p,
            *generate,
            c.key_exchange,
            "pk::generate",
            &[("pk::algorithm", String(algorithm))],
        )?;
    }
    // The same context ID is reused for the second key share
    t.span(
        p,
        c.key_exchange,
        c.handshake,
        "tls::key_exchange",
        &[("tls::group", Word(SECP256R1))],
    )?;
    t.span(
        p,
        c.generate[2],
        c.key_exchange,
        "pk::generate",
        &[
            ("pk::algorithm", String("ECDH")),
            ("pk::curve", String("P-256")),
        ],
    )?;
    Ok(())
}

/// Processing of ServerHello, selecting X25519MLKEM768
fn client_server_hello(t: &mut Trace, p: &Process, c: &ClientContexts) -> Result<()> {
    t.data(
        p,
        c.handshake,
        &[
            ("tls::protocol_version", Word(TLS13)),
            ("tls::ciphersuite", Word(TLS_AES_256_GCM_SHA384)),
        ],
    )?;
    t.span(
        p,
        c.key_exchange2,
        c.handshake,
        "tls::key_exchange",
        &[("tls::group", Word(X25519MLKEM768))],
    )?;
    t.span(
        p,
        c.decapsulate,
        c.key_exchange2,
        "pk::decapsulate",
        &[("pk::algorithm", String("ML-KEM-768"))],
    )?;
    t.span(
        p,
        c.derive,
        c.key_exchange2,
        "pk::derive",
        &[("pk::algorithm", String("X25519"))],
    )?;
    Ok(())
}

/// Verification of the server's certificate chain, reusing the same
/// context ID for each certificate
fn client_verify_cert_chain(
    t: &mut Trace,
    p: &Process,
    c: &ClientContexts,
    bits: &[i64],
) -> Result<()> {
    t.span(
        p,
        c.verify_cert_chain,
        c.handshake,
        "tls::verify_cert_chain",
        &[],
    )?;
    for bits in bits {
        t.span(
            p,
            c.verify_cert,
            c.verify_cert_chain,
            "pk::verify",
            &[("pk::algorithm", String("RSA")), ("pk::bits", Word(*bits))],
        )?;
    }
    Ok(())
}

/// Client and server performing a TLS 1.3 handshake on the same
/// machine, with explicit context hierarchy and `release_context`
/// probes
pub(crate) fn agent_normal() -> Result<Trace> {
    let mut t = Trace::new(1771970000, Duration::from_secs(6643));
    let client = Process::new(74709, &BUILD_ID, "tls-client");
    let server = Process::new(74670, &BUILD_ID, "tls-server");
    let c = ClientContexts::new(0x55a5_24a8_0e40, 0x7f07_a293_4200);

    client_hello(&mut t, &client, &c)?;

    let s_handshake = 0x5590_d9f5_7e60;
    let s_key_exchange = 0x7f65_a8e3_0900;
    let s_sign = 0x7f65_a8e3_1000;
    t.span(
        &server,
        s_handshake,
        NO_PARENT,
        "tls::handshake",
        &[
            ("tls::role", String("server")),
            ("tls::protocol_version", Word(TLS13)),
            ("tls::ciphersuite", Word(TLS_AES_256_GCM_SHA384)),
        ],
    )?;
    t.span(
        &server,
        s_key_exchange,
        s_handshake,
        "tls::key_exchange",
        &[("tls::group", Word(X25519MLKEM768))],
    )?;
    let s_key_exchange_children = [
        ("pk::encapsulate", "ML-KEM-768"),
        ("pk::generate", "X25519"),
        ("pk::derive", "X25519"),
    ];
    for (i, (name, algorithm)) in s_key_exchange_children.into_iter().enumerate() {
        t.span(
            &server,
            0x7f65_a8f3_5300 + (i as i64) * 0x10,
            s_key_exchange,
            name,
            &[("pk::algorithm", String(algorithm))],
        )?;
    }

    client_server_hello(&mut t, &client, &c)?;

    t.span(
        &server,
        s_sign,
        s_handshake,
        "tls::sign",
        &[("tls::signature_algorithm", Word(ED25519))],
    )?;
    t.span(
        &server,
        s_sign + 0x100,
        s_sign,
        "pk::sign",
        &[("pk::algorithm", String("Ed25519"))],
    )?;

    t.span(
        &client,
        c.verify,
        c.handshake,
        "tls::verify",
        &[("tls::signature_algorithm", Word(ED25519))],
    )?;
    t.span(
        &client,
        c.verify_pk,
        c.verify,
        "pk::verify",
        &[("pk::algorithm", String("Ed25519"))],
    )?;
    client_verify_cert_chain(&mut t, &client, &c, &[2048])?;

    t.release_context(&server, s_handshake);
    t.release_context(&client, c.handshake);
    Ok(t)
}
