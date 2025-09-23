/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2022-2025 The crypto-auditing developers. */

/* This file declares a set of high-level functions to insert probe
 * points used for crypto-auditing into the application programs. See
 * <crau/macros.h> for the low-level interface.
 */

#ifndef CRAU_CRAU_H
#define CRAU_CRAU_H

#include <stdint.h>

/* An opaque type that represents a context (e.g., TLS handshake)
 * where crypto-auditing events occur. This should be a unique
 * identifier within a thread.
 */
typedef uint64_t crau_context_t;

/* Types of crypto-auditing event data. CRAU_WORD means an integer in
 * a machine word, CRAU_STRING means a NUL-terminated
 * string. CRAU_BLOB means an explicitly sized binary blob.
 */
enum crau_data_type_t {
	CRAU_WORD,
	CRAU_STRING,
	CRAU_BLOB,
};

/* Push a context CONTEXT onto the thread-local context stack.
 *
 * This call must be followed by a `crau_pop_context`.
 */
void crau_push_context(crau_context_t context);

/* Pop a context from the thread-local context stack. The stack must
 * not be empty.
 */
crau_context_t crau_pop_context(void);

/* Return the context currently active for this thread.
 */
crau_context_t crau_current_context(void);

/* Push a new context (inferred from the call frame) onto the
 * thread-local context stack, optionally emitting events through
 * varargs. Typical usage example is as follows:
 *
 * crau_new_context_with_data(
 *   "name", CRAU_STRING, "pk::sign",
 *   "pk::algorithm", CRAU_STRING, "mldsa",
 *   "pk::bits", CRAU_WORD, 1952 * 8,
 *   NULL);
 *
 * This call must be followed by a `crau_pop_context`.
 */
void crau_new_context_with_data(...);

/* Emit events through varargs, under the current thread-local
   context. Unlike `crau_new_context_with_data`, this does not push a
   new context.
 */
void crau_data(...);

#endif /* CRAU_CRAU_H */
