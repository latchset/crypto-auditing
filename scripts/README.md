## Script for analyzing crypto-auditing event logs

### Flame graphs

To run `flamegraph.py`, you must download ciphersuites and signature
scheme mappings from the IANA registry:

```sh
wget https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
wget https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
wget https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
```

Afterwards, to generate flame graphs from the bundled fixture, run:

```sh
python scripts/flamegraph.py fixtures/output.json
```
