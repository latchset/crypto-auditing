# USDT probe points

## Summary

This document specifies the USDT (user statically defined tracepoints)
probe points used by the crypto-auditing agent.

While [kernel tracepoints][kernel-tracepoints] are not considered part
of the stable ABI, USDT probes defined in user-space libraries could
be treated as stable, and upstream projects might need to preserve
their compatibility across certain release cycles.

Therefore, this proposal aims to define as few USDT probe points as
possible, while still being able to express any type of event of
interest.

## Design details

### Goals

- Easy to integrate: target libraries can be instrumented easily using
  a set of predefined macros, without any external dependencies
- Easy to maintain: the probe interface is stable and imposes no
  versioning requirements
- Performance: the amount of data exchanged between the kernel and
  user space should be reasonably small, and the frequency of these
  exchanges should scale linearly with the actual event frequency

### Non-goals

- Simplicity: the probe points do not necessarily map directly to
  protocol elements

### Probe interface

Programs being traced (typically cryptographic libraries) define USDT
probes as follows:

```c
/* Assert a parent-child relationship between two contexts: a child
 * CONTEXT and its PARENT.
 */
# define CRYPTO_AUDITING_NEW_CONTEXT(context, parent)				\
	DTRACE_PROBE2(crypto_auditing, new_context, context, parent)

/* Declare that CONTEXT is retired and its value may be reused for
 * other purposes.
 */
# define CRYPTO_AUDITING_RELEASE_CONTEXT(context)				\
	DTRACE_PROBE1(crypto_auditing, release_context, context)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the value is a machine word.
 */
# define CRYPTO_AUDITING_WORD_DATA(context, key_ptr, value_ptr)			\
	DTRACE_PROBE3(crypto_auditing, word_data, context, key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. Both the key and the value are
 * treated as NUL-terminated strings.
 */
# define CRYPTO_AUDITING_STRING_DATA(context, key_ptr, value_ptr)			\
	DTRACE_PROBE3(crypto_auditing, string_data, context, key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the size of the value is explicitly
 * given by VALUE_SIZE.
 */
# define CRYPTO_AUDITING_BLOB_DATA(context, key_ptr, value_ptr, value_size)	\
	DTRACE_PROBE4(crypto_auditing, blob_data, context, key_ptr, value_ptr, value_size)
```

These macros can then be invoked in the application logic:

```c
/* Start a TLS client handshake; as the handshake has no parent
 * context, use a non-zero value that never identifies a context
 */
CRYPTO_AUDITING_NEW_CONTEXT(context, 1);

/* Indicate that this context is a TLS handshake */
CRYPTO_AUDITING_STRING_DATA(context, "name", "tls::handshake");

/* Indicate that the local endpoint acts as a client */
CRYPTO_AUDITING_STRING_DATA(context, "tls::role", "client");

/* Indicate that TLS 1.3 has been selected */
CRYPTO_AUDITING_WORD_DATA(context, "tls::protocol_version", 0x0304);

/* The context object is about to be freed */
CRYPTO_AUDITING_RELEASE_CONTEXT(context);
```

where `context` can be any value of machine-word size (a pointer or a
`long`, i.e., a 64-bit integer on LP64 platforms), but must not be
zero. The agent may ignore events whose context is zero.

In library instrumentation, contexts are typically pointers to
allocated objects. If an allocation fails, the pointer will be
NULL. Disallowing zero contexts lets the agent discard events
associated with such failed allocations, without requiring an explicit
NULL check on the library side. To represent a context without a
parent, use a non-zero special value.

#### Protocol between BPF programs and the agent

There are five basic types of USDT probe points to which a BPF
program can attach: `new_context`, `release_context`, `word_data`,
`string_data`, and `blob_data`.

`new_context` asserts a parent-child relationship between two
contexts, `release_context` retires a context, and the remaining three
notify data events:

- `new_context(context, parent)`: indicates a new context under the
  given parent
- `release_context(context)`: indicates that the context is retired
- `word_data(context, key, value)`: indicates an event with a
  machine-word value
- `string_data(context, key, value)`: indicates an event with a
  NUL-terminated string value
- `blob_data(context, key, value, value_size)`: indicates an event
  with a binary blob value

Since contexts are typically pointers to allocated objects, the same
value may be reused for an unrelated context once the original object
is freed. `release_context` allows the library to explicitly declare
that a context is no longer in use, so that subsequent events with the
same value are not associated with the retired context:

- Data events sent to a released context are ignored until it is
  re-created with `new_context`
- A released context can no longer become the parent of other
  contexts, either implicitly or explicitly
- Events already associated with a released context, as well as its
  child contexts, are preserved

Emitting `release_context` is optional; if it is not emitted, the
consumer falls back to heuristics, such as schema-based parent
inference, to disambiguate reused values.

Additionally, there are two extended USDT probe points that combine
the above:

- `new_context_with_data(context, parent, array_ptr, array_size)`
- `data(context, array_ptr, array_size)`

Both take an array of typed data events with the following structure:

```c
struct crypto_auditing_data {
	char *key_ptr;
	void *value_ptr;
	unsigned long value_size;
};
```

where the `value_size` field depends on the type of the value: if the
value is a machine word, it is set to `(unsigned long)-2`; if the
value is a NUL-terminated string, it is set to `(unsigned long)-1`;
otherwise, it is set to the actual size of the value in bytes.

These probe points were introduced to reduce the number of context
switches between the BPF program and the crypto-auditing agent. They
have one drawback, however: the array is read from user-space memory
that may not be paged in, so reading it may fault. Therefore, to
attach to these probe points, the BPF program must be loaded as
[sleepable] and use `bpf_copy_from_user` instead of
`bpf_probe_read_user`.

### Drawbacks and alternatives

#### Overhead of using string keys

While representing event keys as arbitrary-length strings provides
flexibility, it requires BPF programs to read user-space memory using
`bpf_probe_read_user_str`. If this incurs too much overhead, we may
consider using integer code points instead.

#### Using implementation-specific probe points

Instead of key-value based event descriptions, it is possible to
define probe points that directly correspond to particular
implementation details. The following is an attempt along these
lines, using the internal algorithm identifiers of GnuTLS:

```c
client_session_id = *session_id;
max_ver = major;
min_ver = minor;
DTRACE_PROBE3(gnutls_cryptoaudit, client_session_info,
              client_session_id, max_ver, min_ver);

sig_alg = signer->pk_algorithm;
hash_alg = hash;
key_size = pubkey_to_bits(&signer->key.x509->params);
curve_type = signer->key.x509->params.curve;
DTRACE_PROBE4(gnutls_cryptoaudit, private_sign_data,
              sig_alg, hash_alg, key_size, curve_type);
```

This approach has a couple of drawbacks:

- **ABI stability**: since the probe points are exposed through the
  ELF binary, the upstream project would need to maintain them as part
  of its ABI
- **Complexity of event mapping**: if a consumer wants to gather
  statistics on the algorithms used in TLS handshakes, it needs to
  know how they are represented in each supported TLS library

[kernel-tracepoints]: https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html#q-are-tracepoints-part-of-the-stable-abi
[sleepable]: https://lwn.net/Articles/825415/
