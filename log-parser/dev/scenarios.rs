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
/// ecdsa_secp256r1_sha256
const ECDSA_SECP256R1_SHA256: i64 = 0x0403;
/// rsa_pss_rsae_sha256
const RSA_PSS_RSAE_SHA256: i64 = 0x0804;

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

/// Single client handshake, verifying an ECDSA server signature and
/// an RSA certificate chain
fn client_handshake(t: &mut Trace, p: &Process, c: &ClientContexts) -> Result<()> {
    client_hello(t, p, c)?;
    t.sleep(Duration::from_millis(14));
    client_server_hello(t, p, c)?;
    t.span(
        p,
        c.verify,
        c.handshake,
        "tls::verify",
        &[("tls::signature_algorithm", Word(ECDSA_SECP256R1_SHA256))],
    )?;
    t.span(
        p,
        c.verify_pk,
        c.verify,
        "pk::verify",
        &[
            ("pk::algorithm", String("ECDSA")),
            ("pk::curve", String("P-256")),
            ("pk::hash", String("SHA-256")),
        ],
    )?;
    t.sleep(Duration::from_millis(16));
    client_verify_cert_chain(t, p, c, &[4096, 2048])
}

/// Client and server performing TLS 1.3 handshakes, where all
/// contexts in a thread share the same ID and the hierarchy needs to
/// be reconstructed with the schema
pub(crate) fn implicit_context() -> Result<Trace> {
    let mut t = Trace::new(1788127327, Duration::from_secs(3213));
    let client = Process::new(21244, &BUILD_ID, "tls-client");
    let server = Process::new(21234, &BUILD_ID, "tls-server");
    let cli = 0x7fd4_d792_eee0;
    let serv = 0x7efe_b7b2_eee0;

    t.span(
        &client,
        cli,
        cli,
        "tls::handshake",
        &[("tls::role", String("client"))],
    )?;
    t.span(
        &server,
        serv,
        serv,
        "tls::handshake",
        &[
            ("tls::role", String("server")),
            ("tls::protocol_version", Word(TLS13)),
            ("tls::ciphersuite", Word(TLS_AES_256_GCM_SHA384)),
        ],
    )?;
    t.span(
        &server,
        serv,
        serv,
        "tls::key_exchange",
        &[("tls::group", Word(X25519MLKEM768))],
    )?;
    t.span(
        &server,
        serv,
        serv,
        "pk::derive",
        &[("pk::algorithm", String("X25519"))],
    )?;
    t.span(
        &server,
        serv,
        serv,
        "tls::sign",
        &[("tls::signature_algorithm", Word(RSA_PSS_RSAE_SHA256))],
    )?;
    t.sleep(Duration::from_millis(1));
    t.data(
        &client,
        cli,
        &[
            ("tls::protocol_version", Word(TLS13)),
            ("tls::ciphersuite", Word(TLS_AES_256_GCM_SHA384)),
        ],
    )?;
    t.span(
        &client,
        cli,
        cli,
        "tls::key_exchange",
        &[("tls::group", Word(X25519MLKEM768))],
    )?;
    t.span(
        &client,
        cli,
        cli,
        "pk::derive",
        &[("pk::algorithm", String("X25519"))],
    )?;
    // tls::verify is not allowed under tls::verify_cert_chain, so it
    // must become a sibling of it
    t.span(&client, cli, cli, "tls::verify_cert_chain", &[])?;
    t.span(
        &client,
        cli,
        cli,
        "tls::verify",
        &[("tls::signature_algorithm", Word(RSA_PSS_RSAE_SHA256))],
    )?;
    // Subsequent handshakes in the same thread, which must not be
    // nested under the previous one
    t.sleep(Duration::from_millis(5));
    for _ in 0..2 {
        t.span(
            &client,
            cli,
            cli,
            "tls::handshake",
            &[("tls::role", String("client"))],
        )?;
    }
    Ok(t)
}

/// Boot time (in seconds since the epoch) of the since-until scenario
pub(crate) const SINCE_UNTIL_BOOT_TIME: u64 = 1771970837;

/// Three client handshakes, a minute apart from each other, starting
/// at 2026-02-25 08:13:23 JST
pub(crate) fn since_until() -> Result<Trace> {
    let mut t = Trace::new(
        SINCE_UNTIL_BOOT_TIME,
        Duration::from_secs(1771974803 - SINCE_UNTIL_BOOT_TIME) + Duration::from_millis(10),
    );
    let client = Process::new(80123, &BUILD_ID, "tls-client");
    for i in 0..3 {
        let c = ClientContexts::new(0x5616_2e8a_0000 + i * 0x1000, 0x7ffd_3c20_0000 + i * 0x1000);
        client_handshake(&mut t, &client, &c)?;
        t.sleep(Duration::from_secs(60) + Duration::from_millis(200));
    }
    Ok(t)
}
