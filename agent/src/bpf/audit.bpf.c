/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "audit.h"

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
record_new_context (struct pt_regs *ctx)
{
  int err;

  long context;
  err = bpf_usdt_arg (ctx, 0, &context);
  if (err < 0)
    return err;

  long parent;
  err = bpf_usdt_arg (ctx, 1, &parent);
  if (err < 0)
    return err;

  /* Tolerate changes in `struct bpf_stack_build_id` definition in the
     future with longer hash output. */
  unsigned char buf[sizeof(struct bpf_stack_build_id) + MAX_BUILD_ID_SIZE];
  struct bpf_stack_build_id *build_id = (struct bpf_stack_build_id *)buf;
  err = bpf_get_stack (ctx, buf, bpf_core_type_size (struct bpf_stack_build_id),
		       BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);
  if (err < 0)
    return err;

  struct audit_new_context_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_new_context_event_st),
			 0);
  if (!event)
    return -ENOMEM;

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
record_word_data (struct pt_regs *ctx)
{
  int err;

  long context;
  err = bpf_usdt_arg (ctx, 0, &context);
  if (err < 0)
    return err;

  long key_ptr;
  err = bpf_usdt_arg (ctx, 1, &key_ptr);
  if (err < 0)
    return err;

  long value_ptr;
  err = bpf_usdt_arg (ctx, 2, &value_ptr);
  if (err < 0)
    return err;

  struct audit_word_data_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_word_data_event_st),
			 0);
  if (!event)
    return -ENOMEM;

  populate_event_header (&event->base.header,
			 AUDIT_EVENT_DATA,
			 sizeof(*event),
			 context);

  event->base.type = AUDIT_DATA_WORD;
  err = bpf_probe_read_user_str (event->base.key, KEY_SIZE, (void *)key_ptr);
  if (err < 0)
    goto error;
  event->value = value_ptr;

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

static __always_inline int
record_string_data (struct pt_regs *ctx)
{
  int err;

  long context;
  err = bpf_usdt_arg (ctx, 0, &context);
  if (err < 0)
    return err;

  long key_ptr;
  err = bpf_usdt_arg (ctx, 1, &key_ptr);
  if (err < 0)
    return err;

  long value_ptr;
  err = bpf_usdt_arg (ctx, 2, &value_ptr);
  if (err < 0)
    return err;

  struct audit_blob_data_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_blob_data_event_st),
			 0);
  if (!event)
    return -ENOMEM;

  populate_event_header (&event->base.header,
			 AUDIT_EVENT_DATA,
			 sizeof(*event),
			 context);

  event->base.type = AUDIT_DATA_STRING;
  err = bpf_probe_read_user_str (event->base.key, KEY_SIZE, (void *)key_ptr);
  if (err < 0)
    goto error;

  err = bpf_probe_read_user_str (event->value, VALUE_SIZE,
				 (void *)value_ptr);
  if (err < 0)
    goto error;

  event->size = err & (VALUE_SIZE - 1);

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

static __always_inline int
record_blob_data (struct pt_regs *ctx)
{
  int err;

  long context;
  err = bpf_usdt_arg (ctx, 0, &context);
  if (err < 0)
    return err;

  long key_ptr;
  err = bpf_usdt_arg (ctx, 1, &key_ptr);
  if (err < 0)
    return err;

  long value_ptr;
  err = bpf_usdt_arg (ctx, 2, &value_ptr);
  if (err < 0)
    return err;

  long value_size;
  err = bpf_usdt_arg (ctx, 3, &value_size);
  if (err < 0)
    return err;

  struct audit_blob_data_event_st *event =
    bpf_ringbuf_reserve (&ringbuf,
			 sizeof(struct audit_blob_data_event_st),
			 0);
  if (!event)
    return -ENOMEM;

  populate_event_header (&event->base.header,
			 AUDIT_EVENT_DATA,
			 sizeof(*event),
			 context);

  event->base.type = AUDIT_DATA_BLOB;
  err = bpf_probe_read_user_str (event->base.key, KEY_SIZE, (void *)key_ptr);
  if (err < 0)
    goto error;

  value_size &= (VALUE_SIZE - 1);
  err = bpf_probe_read_user (event->value, value_size, (void *)value_ptr);
  if (err < 0)
    goto error;

  event->size = value_size;

  bpf_ringbuf_submit (event, 0);
  return 0;

 error:
  bpf_ringbuf_discard (event, 0);
  return err;
}

SEC("usdt")
int
BPF_USDT(new_context)
{
  return record_new_context(ctx);
}

SEC("usdt")
int
BPF_USDT(word_data)
{
  return record_word_data(ctx);
}

SEC("usdt")
int
BPF_USDT(string_data)
{
  return record_string_data(ctx);
}

SEC("usdt")
int
BPF_USDT(blob_data)
{
  return record_blob_data(ctx);
}

char LICENSE[] SEC("license") = "GPL";
