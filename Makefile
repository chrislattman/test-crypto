java:
	java TLS.java

python:
	python3 tls.py

nodejs:
	node tls.js

go:
	go run go/tls.go

c:
	gcc -Wall -Wextra -Werror -pedantic -std=c99 -o tls tls.c -lcrypto
	./tls

rust:
	cargo run --bin tls

clean:
	rm -rf tls target

.PHONY: java python nodejs go c rust clean
