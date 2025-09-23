# crau

`crau` is a small helper library to define
[crypto-auditing][crypto-auditing] probes in C applications. The
library shall be either statically linked or bundled into the
application itself.

## Getting started

1. Copy all source files (`crau.h`, `crau.c`, and `macros.h`) to your
   application and add them to the build infrastructure (e.g., Makefiles).

1. Define `ENABLE_CRYPTO_AUDITING` to 1, e.g., through `<config.h>`

1. (Optional) Customize macros, e.g., `CRAU_CONTEXT_STACK_DEPTH` for
   your needs. See the header of `crau.c` for the details.

1. Include "crau.h" and instrument the code as follows. See `crau.h`
   or `macros.h` for the documentation:

```c
/* Public key signing operation starts (but the algorithm is not known yet) */
crau_new_context_with_data(
  CRAU_DATA_TYPE_STRING, "name", "pk::sign")
...
/* Signing algorithm and bits are known at this point */
crau_data(
  CRAU_DATA_TYPE_STRING, "pk::algorithm", "mldsa",
  CRAU_DATA_TYPE_WORD, "pk::bits", 1952 * 8)

/* Do the operation */
sig = mldsa_sign(...);

/* Pop the operation context */
crau_pop_context();
```

## Low level macros

Instead of using those helper functions (`crau_*`), it is also
possible to directly instrument the library with `CRAU_` macros
defined in `macros.h`:

```c
/* Public key signing operation starts (but the algorithm is not known yet) */
CRAU_NEW_CONTEXT_WITH_DATAV(
  (crau_context_t)this_function,
  (crau_context_t)parent_function,
  CRAU_STRING_DATA("name", "pk::sign"));
...
/* Signing algorithm and bits are known at this point */
CRAU_DATAV(
  (crau_context_t)this_function,
  CRAU_STRING_DATA("pk::algorithm", "mldsa"),
  CRAU_WORD_DATA("pk::bits", 1952 * 8))

/* Do the operation */
sig = mldsa_sign(...);
```

Note that those macros don't do context management.

## License

MIT

[crypto-auditing]: https://github.com/latchset/crypto-auditing
