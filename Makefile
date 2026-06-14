PREFIX ?= /usr/local
DESTDIR ?=
CARGO ?= cargo

.PHONY: build check install uninstall

build:
	$(CARGO) build --release --locked

check:
	$(CARGO) test --locked

install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 755 target/release/aur-guard "$(DESTDIR)$(PREFIX)/bin/aur-guard"

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/aur-guard"
