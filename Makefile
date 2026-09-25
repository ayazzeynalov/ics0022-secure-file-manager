CC ?= cc
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L
CFLAGS ?= -std=c17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -Wformat-security -O2
LDFLAGS ?=
LDLIBS ?=

TARGET := securepm
SRC := src/main.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean debug

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

debug: CPPFLAGS += -DDEBUG

debug: CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -Wformat-security -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer

debug: LDFLAGS += -fsanitize=address,undefined

debug: clean $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ)
