CC ?= cc
CFLAGS ?= -std=c17 -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security

TARGET = securepm
SRC = src/main.c
OBJ = $(SRC:.c=.o)

.PHONY: all debug clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

debug: CFLAGS += -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
debug: clean $(TARGET)

clean:
	rm -f $(TARGET) $(OBJ)
