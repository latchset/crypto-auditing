.PHONY: check clean mypy flake8

SOURCES = flamegraph.py gen_tables.py
CSV = tls-parameters-4.csv tls-signaturescheme.csv tls-parameters-8.csv

all: tables.py

$(CSV):
	wget https://www.iana.org/assignments/tls-parameters/$@

tables.py: gen_tables.py tls-parameters-4.csv tls-signaturescheme.csv tls-parameters-8.csv
	python gen_tables.py \
		--ciphersuites tls-parameters-4.csv \
		--signature-schemes tls-signaturescheme.csv \
		--supported-groups tls-parameters-8.csv \
		--output $@

mypy: $(SOURCES)
	MYPYPATH=. mypy $(SOURCES)

flake8: $(SOURCES)
	flake8 $(SOURCES)

check: mypy flake8

clean:
	rm -f $(CSV)
