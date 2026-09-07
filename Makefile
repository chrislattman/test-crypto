java:
	java TLS.java

python:
	python3 tls.py

nodejs:
	node tls.js

go:
	go run go/tls.go

c:
	cmake --build build --target run-tls -- --quiet
# 	gcc -Wall -Wextra -Werror -pedantic -std=c99 -o tls tls.c -lcrypto && ./tls

winc:
	cmake --build build --target run-tls -- verbosity:quiet
# 	gcc -Wall -Wextra -Werror -pedantic -std=c99 -o tls tls_cng.c -lbcrypt -lcrypt32 && ./tls

rust:
	cargo run -q --bin tls

csharp:
	dotnet run -v q

clean:
	cmake --build build --target clean && cargo clean && rm -f tls && dotnet clean

.PHONY: java python nodejs go c winc rust csharp clean
