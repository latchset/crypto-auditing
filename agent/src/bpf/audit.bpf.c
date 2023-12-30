/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022-2023 The crypto-auditing developers. */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "audit.h"

#define DEBUG(format, ...)			\
  bpf_trace_printk ("%s: " format, sizeof("%s: " format), \
		    __PRETTY_FUNCTION__, __VA_ARGS__)

#define MAX_EVENTS 16
#define DATA_TYPE_WORD (unsigned long)-2
#define DATA_TYPE_STRING (unsigned long)-1

struct crypto_auditing_data {
  char *key_ptr;
  void *value_ptr;
  unsigned long value_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

static __always_inline void
populate_event_header (struct audit_event_header_st *header,
		       audit_event_type_t type,
		       size_t size,
		       long context)
{
  header->size = size;
  header->type = type;
  header->pid_tgid = bpf_get_current_pid_tgid ();
  header->context = context;
  header->ktime = bpf_ktime_get_boot_ns ();
}

static __always_inline int
record_new_context (struct pt_regs *ctx, long context, long parent)
{
  int err;

  /* Tolerate changes in `struct bpf_stack_build_id` definition in the
     future with longer hash output. */
  unsigned char buf[sizeof(struct bpf_stack_build_id) + MAX_BUILD_ID_SIZE];
  struct bpf_stack_build_id *build_id = (struct bpf_stack_build_id *)buf;
  err = bpf_get_stack (ctx, buf, bpf_core_type_size (struct bpf_stack_build_id),
		       BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);
  if (err < 0)
    {
      DEBUG ("unable to extract build-id: %ld\n", err);
      return err;
    }

  struct audit_new_context_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_new_context_event_st),
			 0);
  if (!event)
    {
      DEBUG ("unable to allocate ringbuf entry: %ld\n", -ENOMEM);
      return -ENOMEM;
    }

  populate_event_header (&event->header,
			 AUDIT_EVENT_NEW_CONTEXT,
			 sizeof(*event),
			 context);
  event->parent = parent;

  if (BPF_CORE_READ_BITFIELD(build_id, status) & BPF_STACK_BUILD_ID_VALID)
    {
      event->origin_size = bpf_core_field_size (build_id->build_id);
      bpf_core_read (event->origin, event->origin_size, &build_id->build_id);
    }

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

static __always_inline int
record_word_data (struct pt_regs *ctx, long context, const char *key_ptr,
		  long value)
{
  int err;

  struct audit_word_data_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_word_data_event_st),
			 0);
  if (!event)
    {
      DEBUG ("unable to allocate ringbuf entry: %ld\n", -ENOMEM);
      return -ENOMEM;
    }

  populate_event_header (&event->base.header,
			 AUDIT_EVENT_DATA,
			 sizeof(*event),
			 context);

  event->base.type = AUDIT_DATA_WORD;
  err = bpf_probe_read_user_str (event->base.key, KEY_SIZE, (void *)key_ptr);
  if (err < 0)
    {
      DEBUG ("unable to read event key: %ld\n", err);
      goto error;
    }
  event->value = value;

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

static __always_inline int
record_string_data (struct pt_regs *ctx, long context, const char *key_ptr,
		    const char *value_ptr)
{
  int err;

  struct audit_blob_data_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_blob_data_event_st),
			 0);
  if (!event)
    {
      DEBUG ("unable to allocate ringbuf entry: %ld\n", -ENOMEM);
      return -ENOMEM;
    }

  populate_event_header (&event->base.header,
			 AUDIT_EVENT_DATA,
			 sizeof(*event),
			 context);

  event->base.type = AUDIT_DATA_STRING;
  err = bpf_probe_read_user_str (event->base.key, KEY_SIZE, (void *)key_ptr);
  if (err < 0)
    {
      DEBUG ("unable to read event key: %ld\n", err);
      goto error;
    }

  err = bpf_probe_read_user_str (event->value, VALUE_SIZE,
				 (void *)value_ptr);
  if (err < 0)
    {
      DEBUG ("unable to read event data: %ld\n", err);
      goto error;
    }

  event->size = (unsigned long)err;

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

static __always_inline int
record_blob_data (struct pt_regs *ctx, long context, const char *key_ptr)
{
  int err;

  long value;
  err = bpf_usdt_arg (ctx, 3, &value);
  if (err < 0)
    {
      DEBUG ("unable to determine value size: %ld\n", err);
      return err;
    }
  if (value < 0 || value > VALUE_SIZE)
    {
      DEBUG ("value size out of range: %ld\n", value);
      return -EINVAL;
    }
  unsigned long value_size = (unsigned long)value;

  struct audit_blob_data_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_blob_data_event_st),
			 0);
  if (!event)
    {
      DEBUG ("unable to allocate ringbuf entry: %ld\n", -ENOMEM);
      return -ENOMEM;
    }

  populate_event_header (&event->base.header,
			 AUDIT_EVENT_DATA,
			 sizeof(*event),
			 context);

  event->base.type = AUDIT_DATA_BLOB;
  err = bpf_probe_read_user_str (event->base.key, KEY_SIZE, (void *)key_ptr);
  if (err < 0)
    {
      DEBUG ("unable to read event key: %ld\n", err);
      goto error;
    }

  if (value_size > 0)
    {
      long value_ptr;

      err = bpf_usdt_arg (ctx, 2, &value_ptr);
      if (err < 0)
	{
	  DEBUG ("unable to read value: %ld\n", err);
	  goto error;
	}

      err = bpf_probe_read_user (event->value, value_size, (void *)value_ptr);
      if (err < 0)
	{
	  DEBUG ("unable to read event data: %ld\n", err);
	  goto error;
	}
    }

  event->size = value_size;

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

/* This is similar to record_blob_data but always assumes VALUE_PTR is
 * present.
 */
static __always_inline int
record_blob_data_explicit (struct pt_regs *ctx, long context, const char *key_ptr,
			   const void *value_ptr, unsigned long value_size)
{
  int err;

  if (value_size > VALUE_SIZE)
    {
      DEBUG ("value size out of range: %lu\n", value_size);
      return -EINVAL;
    }

  struct audit_blob_data_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_blob_data_event_st),
			 0);
  if (!event)
    {
      DEBUG ("unable to allocate ringbuf entry: %ld\n", -ENOMEM);
      return -ENOMEM;
    }

  populate_event_header (&event->base.header,
			 AUDIT_EVENT_DATA,
			 sizeof(*event),
			 context);

  event->base.type = AUDIT_DATA_BLOB;
  err = bpf_probe_read_user_str (event->base.key, KEY_SIZE, (void *)key_ptr);
  if (err < 0)
    {
      DEBUG ("unable to read event key: %ld\n", err);
      goto error;
    }

  if (value_size > 0)
    {
      err = bpf_probe_read_user (event->value, value_size, (void *)value_ptr);
      if (err < 0)
	{
	  DEBUG ("unable to read event data: %ld\n", err);
	  goto error;
	}
    }

  event->size = value_size;

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

static __always_inline int
record_data (struct pt_regs *ctx,
	     long context,
	     const struct crypto_auditing_data *array_ptr,
	     unsigned long array_size)
{
  struct crypto_auditing_data events[MAX_EVENTS];
  int err;

  if (array_size > MAX_EVENTS)
    {
      DEBUG ("value size out of range: %lu\n", array_size);
      return -EINVAL;
    }
  array_size &= MAX_EVENTS - 1;

  err = bpf_probe_read_user (events,
			     array_size * sizeof (struct crypto_auditing_data),
			     array_ptr);
  if (err < 0)
    {
      DEBUG ("unable to read from data array: %ld\n", err);
      return err;
    }

  for (unsigned long i = 0; i < array_size; i++)
    {
      switch (events[i].value_size)
	{
	case DATA_TYPE_WORD:
	  err = record_word_data (ctx, context,
				  events[i].key_ptr,
				  (long) events[i].value_ptr);
	  if (err < 0)
	    DEBUG ("unable to process word data: %ld\n", err);
	  break;

	case DATA_TYPE_STRING:
	  err = record_string_data (ctx, context,
				    events[i].key_ptr,
				    (const char *) events[i].value_ptr);
	  if (err < 0)
	    DEBUG ("unable to process string data: %ld\n", err);
	  break;

	default:
	  err = record_blob_data_explicit (ctx, context,
					   events[i].key_ptr,
					   events[i].value_ptr,
					   events[i].value_size);
	  if (err < 0)
	    DEBUG ("unable to process blob data: %ld\n", err);
	  break;
	}

      if (err < 0)
	break;
    }

  return err;
}

static __always_inline int
record_new_context_with_data (struct pt_regs *ctx, long context, long parent,
			      struct crypto_auditing_data *array_ptr,
			      unsigned long array_size)
{
  int err;

  err = record_new_context (ctx, context, parent);
  if (err < 0)
    return err;

  return record_data (ctx, context, array_ptr, array_size);
}

SEC("usdt")
int
BPF_USDT(new_context, long context, long parent)
{
  return record_new_context (ctx, context, parent);
}

SEC("usdt")
int
BPF_USDT(word_data, long context, const char *key_ptr, long value)
{
  return record_word_data (ctx, context, key_ptr, value);
}

SEC("usdt")
int
BPF_USDT(string_data, long context, const char *key_ptr,
	 const char *value_ptr)
{
  return record_string_data (ctx, context, key_ptr, value_ptr);
}

SEC("usdt")
int
BPF_USDT(blob_data, long context, const char *key_ptr)
{
  return record_blob_data (ctx, context, key_ptr);
}

SEC("usdt")
int
BPF_USDT(data, long context, const struct crypto_auditing_data *array_ptr,
	 unsigned long array_size)
{
  return record_data (ctx, context, array_ptr, array_size);
}

SEC("usdt")
int
BPF_USDT(new_context_with_data, long context, long parent,
	 void *array_ptr, unsigned long array_size)
{
  return record_new_context_with_data (ctx, context, parent, array_ptr,
				       array_size);
}

char LICENSE[] SEC("license") = "GPL";
