# USDT probe points

## Summary

This document specifies the USDT (user statically defined tracepoints)
probe points used by the crypto-auditing agent.

While tracepoints defined in the [kernel][kernel-tracepoints] are not
considered as part of the stable ABI, USDT defined in userspace
libraries could be treated as stable and the upstream projects might
need to preserve compatibility for certain release cycles.

Therefore, this proposal aims to define USDT probe points as few as
possible to express any type of interesting events.

## Design details

### Goals

- Easy to integrate: target libraries are easily instrumented using a
  set of pre-defined macros, without any external dependency
- Easy to maintain: the probe interface is stable and does not impose
  any versioning requirements
- Performance: the amount of data exchanged between the kernel and
  user space programs should be reasonably small, while the frequency
  of data exchanges between the kernel and user space should be
  considered linear to the actual event frequency

### Non-goals

- Simplicity: the probe points may not directly map to the protocol
  element

### Probe interface

Programs being traced (typically cryptographic libraries) define USDT
probes as follows:

```c
/* Assert a parent-child relationship between two contexts, a child
 * CONTEXT and its PARENT.
 */
# define CRYPTO_AUDITING_NEW_CONTEXT(context, parent)				\
	DTRACE_PROBE2(crypto_auditing, new_context, context, parent)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the value is in the size of machine
 * word
 */
# define CRYPTO_AUDITING_WORD_DATA(context, key_ptr, value_ptr)			\
	DTRACE_PROBE3(crypto_auditing, word_data, context, key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. Both the key and value are
 * treated as a NUL-terminated string
 */
# define CRYPTO_AUDITING_STRING_DATA(context, key_ptr, value_ptr)			\
	DTRACE_PROBE3(crypto_auditing, string_data, context, key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the value is explicitly sized with
 * VALUE_SIZE
 */
# define CRYPTO_AUDITING_BLOB_DATA(key_ptr, context, value_ptr, value_size)	\
	DTRACE_PROBE4(crypto_auditing, blob_data, context, key_ptr, value_ptr, value_size)
```

These macros can be invoked in the application logic:

```c
/* Start TLS client handshake */
CRYPTO_AUDITING_NEW_CONTEXT(context, NULL);

/* Indicate that this context is about TLS client handshake */
CRYPTO_AUDITING_STRING_DATA(context, "name", "tls::handshake_client");

/* Indicate that TLS 1.3 is selected */
CRYPTO_AUDITING_WORD_DATA(context, "tls::protocol_version", 0x0304);
```

where `context` can be any object with the size of a machine word (a
pointer or `long`, i.e., a 64-bit integer on LP64 platforms), but must
not be zero. The agent may ignore events if their contexts are
zero.

In library instrumentation, context objects are typically pointers to
allocated objects. If allocation fails, the pointers will be
NULL. Prohibiting all-zero contexts would help prevent this situation,
without imposing an explicit NULL check on the library side. To
represent a context without a parent, use a non-zero special value.

#### Protocol between BPF programs and the agent

There are 4 basic types of USDT probe points to which a BPF program
can attach: `new_context`, `word_data`, `string_data`, and
`blob_data`.

`new_context` is used for asserting a parent-child relationship
between two contexts, while the latter 3 are used for notifying data
events:

- `new_context(context, parent)`: indicate a context under a given parent
- `word_data(context, key, value)`: indicate an event of a machine
  word
- `string_data(context, key, value)`: indicate an event of a
  NUL-terminated string
- `blob_data(context, key, value, value_size)`: indicate an event of a
  binary blob

Additionally, there are 2 extended USDT probe points which combine the
above:

- `new_context_with_data(context, parent, array_ptr, array_size)`
- `data(context, array_ptr, array_size)`

Both probe points take a typed array of data events in the following
structure:

```c
struct crypto_auditing_data {
	char *key_ptr;
	void *value_ptr;
	unsigned long value_size;
};
```

where the `value_size` field is set depending on the type of the
value. If the value is a machine word, it is set to 0xfffffffe (= -2,
in 2's complement representation). If the value is a NUL-terminated
string, it is set to 0xffffffff (= -1). Otherwise, it is set to the
actual size of the value.

These probe points were introduced to reduce the number of context
switches between a BPF program and the crypto-auditing agent. There
is, however, one drawback: since reading the contents of the array is
not an atomic operation, the memory may be unmapped. Therefore, to
attach those probe points, the BPF program must be loaded as
[sleepable] and using `bpf_copy_from_user` instead of
`bpf_probe_read_user`.

### Drawbacks and alternatives

#### Overhead of using string keys

While storing event keys as an arbitrary-length string brings
flexibility, that would require BPF programs to access memory in
userspace, using `bpf_probe_read_user_str`.  If that imposes too much
overhead, we may consider using integer codepoints instead.

#### Using implementation specific probe points

Instead of using a key-value based event description, it is possible
to define probe points that directly corresponds to particular
implementation detail.  The following is an attempt along these lines,
assuming internal algorithm identifiers used in GnuTLS:

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

- **ABI stability**: since the probe points are exposed through ELF
  binary, the upstream project would need to maintain them as part of
  the ABI
- **Complexity of event mapping**: suppose a consumer wants to take a
  statistics of algorithms used in TLS handshake, the consumer needs
  to have knowledge on how those are represented in supported TLS
  libraries

[kernel-tracepoints]: https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html#q-are-tracepoints-part-of-the-stable-abi
[protocol-version]: https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3.1
[sleepable]: https://lwn.net/Articles/825415/
