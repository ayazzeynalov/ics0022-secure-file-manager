CC ?= cc
CFLAGS ?= -std=c17 -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security

TARGET = securepm
SRC = src/main.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
