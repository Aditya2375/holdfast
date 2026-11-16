CC = cc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror -Isrc
all: build/holdfast build/payload
build:
	mkdir -p build
build/holdfast: src/runtime.c src/policy.h | build
	$(CC) $(CFLAGS) src/runtime.c -o $@
build/payload: tests/payload.c src/policy.h | build
	$(CC) $(CFLAGS) -static tests/payload.c -o $@
clean:
	rm -rf build
.PHONY: all clean
test: all
	python3 tests/native.py
.PHONY: test
ubuild:
	mkdir -p build
	$(CC) $(CFLAGS) -O1 -g -fsanitize=undefined -fno-sanitize-recover=all src/runtime.c -o build/holdfast-ubsan
ubsan: all ubuild
	HOLDFAST_BIN=build/holdfast-ubsan python3 tests/native.py
.PHONY: ubuild ubsan
