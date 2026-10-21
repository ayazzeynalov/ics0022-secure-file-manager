CC ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security
PKG_CONFIG ?= pkg-config

# Prefer pkg-config; Homebrew OpenSSL is outside macOS's default search path.
OPENSSL_PREFIX ?= $(shell command -v brew >/dev/null 2>&1 && brew --prefix openssl@3 2>/dev/null)
ifneq ($(strip $(OPENSSL_PREFIX)),)
OPENSSL_CFLAGS = -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS = -L$(OPENSSL_PREFIX)/lib -lcrypto
endif
ifeq ($(shell $(PKG_CONFIG) --exists libcrypto 2>/dev/null && echo yes),yes)
OPENSSL_CFLAGS = $(shell $(PKG_CONFIG) --cflags libcrypto)
OPENSSL_LIBS = $(shell $(PKG_CONFIG) --libs libcrypto)
endif
OPENSSL_LIBS ?= -lcrypto

TARGET = securepm
SRC = src/main.c src/cli.c src/crypto.c src/auth.c src/storage.c
OBJ = $(SRC:src/%.c=build/%.o)
DEP = $(OBJ:.o=.d) build/test_crypto.d build/test_auth.d build/test_storage.d

.PHONY: all clean test check-openssl
all: $(TARGET)

$(TARGET): $(OBJ) | check-openssl
	$(CC) $(LDFLAGS) $(OBJ) $(OPENSSL_LIBS) $(LDLIBS) -o $@

build/%.o: src/%.c | build check-openssl
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -std=c17 -MMD -MP -c $< -o $@

build:
	mkdir -p $@

build/check_openssl: tools/check_openssl.c | build
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -std=c17 $(LDFLAGS) $< $(OPENSSL_LIBS) $(LDLIBS) -o $@

check-openssl: build/check_openssl
	./build/check_openssl

build/test_crypto.o: tests/test_crypto.c | build check-openssl
	$(CC) $(CPPFLAGS) -Isrc $(OPENSSL_CFLAGS) $(CFLAGS) -std=c17 -MMD -MP -c $< -o $@

build/test_crypto: build/test_crypto.o build/crypto.o | check-openssl
	$(CC) $(LDFLAGS) $^ $(OPENSSL_LIBS) $(LDLIBS) -o $@

build/test_auth.o: tests/test_auth.c | build check-openssl
	$(CC) $(CPPFLAGS) -Isrc $(OPENSSL_CFLAGS) $(CFLAGS) -std=c17 -MMD -MP -c $< -o $@

build/test_auth: build/test_auth.o build/auth.o build/crypto.o | check-openssl
	$(CC) $(LDFLAGS) $^ $(OPENSSL_LIBS) $(LDLIBS) -o $@

build/test_storage.o: tests/test_storage.c | build check-openssl
	$(CC) $(CPPFLAGS) -Isrc $(OPENSSL_CFLAGS) $(CFLAGS) -std=c17 -MMD -MP -c $< -o $@

build/test_storage: build/test_storage.o build/storage.o | check-openssl
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

test: $(TARGET) build/test_crypto build/test_auth build/test_storage
	sh tests/smoke.sh ./$(TARGET)
	./build/test_crypto
	./build/test_auth
	./build/test_storage

clean:
	rm -rf build
	rm -f $(TARGET) src/*.o

-include $(DEP)
