#ifndef SECUREPM_STORAGE_H
#define SECUREPM_STORAGE_H

#include <stddef.h>

#define STORAGE_DIRECTORY_MODE 0700
#define STORAGE_FILE_MODE 0600
#define STORAGE_FILENAME_MAX_BYTES 128
#define STORAGE_MAX_FILE_BYTES (16U * 1024U * 1024U)

#define STORAGE_READ_ERROR (-1)
#define STORAGE_READ_MISSING 0
#define STORAGE_READ_OK 1

enum storage_area {
    STORAGE_AREA_ROOT = 0,
    STORAGE_AREA_VAULTS = 1
};

struct storage {
    int root_fd;
    int vaults_fd;
};

#define STORAGE_INITIALIZER { -1, -1 }

/* Uses the absolute HOME environment path. Every path component must be a real
 * directory rather than a symlink, and HOME must be owned by the effective user.
 * Callers must initialize the context with STORAGE_INITIALIZER. */
int storage_init(struct storage *storage);
void storage_close(struct storage *storage);

/* Filenames are single controlled components: 1..128 ASCII bytes, beginning
 * with an alphanumeric byte and containing only alphanumerics, '.', '_', '-'.
 * The read result is allocated with malloc() and must be released with
 * storage_free(). Missing files are distinct from unsafe/error conditions. */
int storage_read_file(const struct storage *storage, enum storage_area area,
                      const char *filename, size_t maximum_size,
                      unsigned char **data, size_t *data_length);
void storage_free(void *data);

/* Atomically installs non-secret metadata or already-encrypted bytes. This
 * module cannot identify plaintext; callers must never pass passwords, VMKs,
 * or unencrypted credential records. */
int storage_atomic_write(const struct storage *storage, enum storage_area area,
                         const char *filename,
                         const unsigned char *data, size_t data_length);

#endif
