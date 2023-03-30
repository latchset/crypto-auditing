## Script for analyzing crypto-auditing event logs

### Flame graphs

To run `flamegraph.py`, you must generate `tables.py` from the IANA
registry data, with the make command:

```sh
make
```

Afterwards, to generate flame graphs from the bundled fixture, run:

```sh
python flamegraph.py ../fixtures/output.json
```
