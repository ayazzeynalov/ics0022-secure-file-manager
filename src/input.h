#ifndef SECUREPM_INPUT_H
#define SECUREPM_INPUT_H

#include <stddef.h>

#define INPUT_READ_ERROR (-1)
#define INPUT_READ_EOF 0
#define INPUT_READ_OK 1
#define INPUT_READ_TOO_LONG 2
#define INPUT_READ_INTERRUPTED 3

int input_initialize(void);
void input_cleanup(void);

int input_read_line(const char *prompt, char *buffer, size_t capacity,
                    size_t *length);
int input_read_secret(const char *prompt, char *buffer, size_t capacity,
                      size_t *length);

int input_interrupted_signal(void);

#endif
