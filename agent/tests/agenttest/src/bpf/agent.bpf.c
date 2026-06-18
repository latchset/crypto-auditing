/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2023 The crypto-auditing developers. */

#include "vmlinux.h"

/* bpf_helpers.h from libbpf 1.6 had a conflicting declaration of
 * bpf_stream_vprintk.
 */
#include <bpf/libbpf_version.h>
#if defined(LIBBPF_MAJOR_VERSION) && defined(LIBBPF_MINOR_VERSION) && \
  LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION == 6
# define bpf_stream_vprintk bpf_stream_vprintk_UNUSED
#endif
#include <bpf/usdt.bpf.h>

#define MAX_DATA_SIZE 512

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

SEC("usdt")
int
BPF_USDT(event_group, long count)
{
  long *value;
  long err;

  value = bpf_ringbuf_reserve (&ringbuf, sizeof(*value), 0);
  if (value)
    {
      *value = count;
      bpf_ringbuf_submit (value, 0);
    }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
