/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
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
