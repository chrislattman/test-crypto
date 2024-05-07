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

clean:
	rm tls

.PHONY: java python nodejs go c clean
