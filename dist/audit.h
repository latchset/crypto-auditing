/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2022-2023 The crypto-auditing developers. */

/* This file defines probe points used by crypto-auditing. */

#ifdef ENABLE_CRYPTO_AUDITING

# ifdef HAVE_SYS_SDT_H
#  include <sys/sdt.h>
# endif

/* Introduce a new context CONTEXT, derived from PARENT */
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
# define CRYPTO_AUDITING_BLOB_DATA(context, key_ptr, value_ptr, value_size)	\
	DTRACE_PROBE4(crypto_auditing, blob_data, context, key_ptr, value_ptr, value_size)

struct crypto_auditing_data {
	char *key_ptr;
	void *value_ptr;
	unsigned long value_size;
};

# define CRYPTO_AUDITING_WORD(key_ptr, value_ptr) \
	{ (char *)(key_ptr), (void *)(intptr_t)(value_ptr), (unsigned long)-2 }
# define CRYPTO_AUDITING_STRING(key_ptr, value_ptr) \
	{ (char *)(key_ptr), (void *)(value_ptr), (unsigned long)-1 }
# define CRYPTO_AUDITING_BLOB(key_ptr, value_ptr, value_size) \
	{ (char *)(key_ptr), (void *)(value_ptr), value_size }

/* Assert multiple events (16 at maxiumum) at once as a typed
 * array. The VALUE_SIZE field of each element indicates the type of
 * event: -2 means a word, -1 means a NUL-terminated string, and any
 * other value means a blob with the length of VALUE_SIZE.
 */
# define CRYPTO_AUDITING_DATA(context, array_ptr, array_size) \
	DTRACE_PROBE3(crypto_auditing, data, context, array_ptr, array_size)

# define CRYPTO_AUDITING_DATAV(context, ...) ({	\
	struct crypto_auditing_data __crypto_auditing_events[] = { __VA_ARGS__ }; \
	CRYPTO_AUDITING_DATA(context, \
		__crypto_auditing_events, \
		sizeof (__crypto_auditing_events) / sizeof (__crypto_auditing_events[0])); \
})

/* Introduce a new context CONTEXT, derived from PARENT, as well as
 * assert multiple events.
 */
# define CRYPTO_AUDITING_NEW_CONTEXT_WITH_DATA(context, parent, array_ptr, array_size) \
	DTRACE_PROBE4(crypto_auditing, new_context_with_data, context, parent, array_ptr, array_size)

# define CRYPTO_AUDITING_NEW_CONTEXT_WITH_DATAV(context, parent, ...) ({ \
	struct crypto_auditing_data __crypto_auditing_events[] = { __VA_ARGS__ }; \
	CRYPTO_AUDITING_NEW_CONTEXT_WITH_DATA(context, parent, \
		__crypto_auditing_events, \
		sizeof (__crypto_auditing_events) / sizeof (__crypto_auditing_events[0])); \
})

#else

# define CRYPTO_AUDITING_NEW_CONTEXT(context, parent)
# define CRYPTO_AUDITING_WORD_DATA(context, key_ptr, value_ptr)
# define CRYPTO_AUDITING_STRING_DATA(context, key_ptr, value_ptr)
# define CRYPTO_AUDITING_BLOB_DATA(context, key_ptr, value_ptr, value_size)
# define CRYPTO_AUDITING_WORD(key_ptr, value_ptr)
# define CRYPTO_AUDITING_STRING(key_ptr, value_ptr)
# define CRYPTO_AUDITING_BLOB(key_ptr, value_ptr, value_size)
# define CRYPTO_AUDITING_DATA(context, array_ptr, array_size)
# define CRYPTO_AUDITING_DATAV(context, ...)
# define CRYPTO_AUDITING_NEW_CONTEXT_WITH_DATA(context, parent, array_ptr, array_size)
# define CRYPTO_AUDITING_NEW_CONTEXT_WITH_DATAV(context, parent, ...)

#endif /* ENABLE_CRYPTO_AUDITING */
