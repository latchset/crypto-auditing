/* SPDX-License-Identifier: GPL-2.0 */

/* This file should be self-contained and do not rely on any system
 * headers, because it is used by both the BPF program (audit.bpf.c)
 * and the generated Rust bindings.
 */

typedef enum
  {
    AUDIT_DATA_WORD = 0,
    AUDIT_DATA_STRING = 1,
    AUDIT_DATA_BLOB = 2,
  } audit_data_type_t;

#define KEY_SIZE 32
#define VALUE_SIZE 64

typedef enum
  {
    AUDIT_EVENT_NEW_CONTEXT = 0,
    AUDIT_EVENT_DATA = 1,
  } audit_event_type_t;

struct audit_event_header_st
{
  unsigned long int size;
  audit_event_type_t type;
  unsigned long int pid_tgid;	/* u64 */
  long context;
  unsigned long int ktime;	/* u64 */
};

#define MAX_BUILD_ID_SIZE 64

struct audit_new_context_event_st
{
  struct audit_event_header_st header;
  long parent;
  unsigned char origin[MAX_BUILD_ID_SIZE];
  unsigned long int origin_size;
};

struct audit_data_event_st
{
  struct audit_event_header_st header;
  audit_data_type_t type;
  char key[KEY_SIZE];
};

struct audit_word_data_event_st
{
  struct audit_data_event_st base;
  long value;
};

struct audit_blob_data_event_st
{
  struct audit_data_event_st base;
  unsigned char value[VALUE_SIZE];
  unsigned long int size;
};
