CSV = tls-parameters-4.csv tls-signaturescheme.csv tls-parameters-8.csv

all: tables.py

$(CSV):
	wget https://www.iana.org/assignments/tls-parameters/$@

tables.py: tls-parameters-4.csv tls-signaturescheme.csv tls-parameters-8.csv
	python gen-tables.py \
		--ciphersuites tls-parameters-4.csv \
		--signature-schemes tls-signaturescheme.csv \
		--supported-groups tls-parameters-8.csv \
		--output $@

clean:
	rm -f $(CSV)
