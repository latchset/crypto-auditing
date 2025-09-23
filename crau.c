/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2022-2025 The crypto-auditing developers. */

/* This file implements the functions a set of high-level functions to
 * insert probe points used for crypto-auditing into the application
 * programs.
 *
 * This file is typically copied into the application's source code as
 * a copylib, and the following configuration macros can be used to
 * override the behavior of the implementation:
 *
 * * CRAU_CONTEXT_STACK_DEPTH: depth of the thread-local context stack
 *   (default: 3)
 *
 * * CRAU_RETURN_ADDRESS: return address of the current function
 *   (default: auto-detected)
 *
 * * CRAU_THREAD_LOCAL: thread-local modifier of the C language
 *   (default: auto-detected)
 *
 * * CRAU_MAYBE_UNUSED: an attribute to suppress warnings when a
 *   function argument is not used in the function body (default:
 *   auto-detected)
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "crau.h"

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>

#ifdef ENABLE_CRYPTO_AUDITING

#ifndef CRAU_CONTEXT_STACK_DEPTH
#define CRAU_CONTEXT_STACK_DEPTH 3
#endif /* CRAU_CONTEXT_STACK_DEPTH */

#ifndef CRAU_THREAD_LOCAL
# ifdef thread_local
#  define CRAU_THREAD_LOCAL thread_local
# elif __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#  define CRAU_THREAD_LOCAL _Thread_local
# elif defined(_MSC_VER)
#  define CRAU_THREAD_LOCAL __declspec(thread)
# elif defined(__GNUC__)
#  define CRAU_THREAD_LOCAL __thread
# else
#  error "thread_local support is required; define CRAU_THREAD_LOCAL"
# endif
#endif /* CRAU_THREAD_LOCAL */

#ifndef CRAU_RETURN_ADDRESS
# ifdef __GNUC__
#  define CRAU_RETURN_ADDRESS __builtin_return_address(0)
# elif defined(__CC_ARM)
#  define CRAU_RETURN_ADDRESS __return_address()
# else
#  error "__builtin_return_address support is required; define CRAU_RETURN_ADDRESS"
# endif
#endif /* CRAU_RETURN_ADDRESS */

static CRAU_THREAD_LOCAL crau_context_t context_stack[CRAU_CONTEXT_STACK_DEPTH] = {
	0,
};
static CRAU_THREAD_LOCAL size_t context_stack_top = 0;

void crau_push_context(crau_context_t context)
{
	assert(context_stack_top < CRAU_CONTEXT_STACK_DEPTH);
	context_stack[context_stack_top++] = context;
}

crau_context_t crau_pop_context(void)
{
	assert(context_stack_top > 0);
	return context_stack[--context_stack_top];
}

crau_context_t crau_current_context(void)
{
	if (context_stack_top == 0)
		return ~0UL;
	return context_stack[context_stack_top - 1];
}

static inline size_t
accumulate_datav(struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS],
		 va_list ap)
{
	size_t count = 0;

	for (; count < CRAU_MAX_DATA_ELEMS;) {
		switch (va_arg(ap, enum crau_data_type_t)) {
		case CRAU_DATA_TYPE_WORD:
			data[count].key_ptr = va_arg(ap, char *);
			data[count].value_ptr = (void *)va_arg(ap, intptr_t);
			data[count].value_size = (unsigned long)-2;
			count++;
			break;
		case CRAU_DATA_TYPE_STRING:
			data[count].key_ptr = va_arg(ap, char *);
			data[count].value_ptr = (void *)va_arg(ap, char *);
			data[count].value_size = (unsigned long)-1;
			break;
		case CRAU_DATA_TYPE_BLOB:
			data[count].key_ptr = va_arg(ap, char *);
			data[count].value_ptr = va_arg(ap, void *);
			data[count].value_size = va_arg(ap, unsigned long);
			count++;
			break;
		}
	}

	return count;
}

void crau_new_context_with_data(...)
{
	crau_context_t context = CRAU_RETURN_ADDRESS;
	struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS];
	size_t count;
	va_list ap;

	va_start(ap);
	count = accumulate_datav(data, ap);
	va_end(ap);

	CRAU_NEW_CONTEXT_WITH_DATA(context, crau_current_context(), data,
				   count);
	crau_push_context(context);
}

void crau_data(...)
{
	struct crypto_auditing_data data[CRAU_MAX_DATA_ELEMS];
	size_t count;
	va_list ap;

	va_start(ap);
	count = accumulate_datav(data, ap);
	va_end(ap);

	CRAU_DATA(crau_current_context(), data, count);
}

#else

#ifndef CRAU_MAYBE_UNUSED
# if defined(__has_c_attribute) && \
  __has_c_attribute (__maybe_unused__)
#  define CRAU_MAYBE_UNUSED [[__maybe_unused__]]
# elif defined(__GNUC__)
#  define CRAU_MAYBE_UNUSED __attribute__((__unused__))
# endif
#endif /* CRAU_MAYBE_UNUSED */

void crau_push_context(crau_context_t context CRAU_MAYBE_UNUSED)
{
}

crau_context_t crau_pop_context(void)
{
	return ~0UL;
}

crau_context_t crau_current_context(void)
{
	return ~0UL;
}

void crau_new_context_with_data(...)
{
}

void crau_data(...)
{
}

#endif /* ENABLE_CRYPTO_AUDITING */
