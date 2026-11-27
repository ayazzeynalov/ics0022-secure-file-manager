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

enum storage_atomic_result {
    STORAGE_ATOMIC_ERROR = 0,
    STORAGE_ATOMIC_DURABLE = 1,
    STORAGE_ATOMIC_INSTALLED = 2
};

struct storage {
    int home_fd;
    int root_fd;
    int vaults_fd;
};

#define STORAGE_INITIALIZER { -1, -1, -1 }

struct storage_lock {
    int descriptor;
    int held;
};

#define STORAGE_LOCK_INITIALIZER { -1, 0 }

int storage_init(struct storage *storage);
void storage_close(struct storage *storage);

int storage_read_file(const struct storage *storage, enum storage_area area,
                      const char *filename, size_t maximum_size,
                      unsigned char **data, size_t *data_length);
void storage_free(void *data);

int storage_atomic_write(const struct storage *storage, enum storage_area area,
                         const char *filename,
                         const unsigned char *data, size_t data_length);
enum storage_atomic_result storage_atomic_write_result(
    const struct storage *storage, enum storage_area area,
    const char *filename, const unsigned char *data, size_t data_length);

int storage_atomic_replace(const struct storage *storage,
                           enum storage_area area, const char *filename,
                           const unsigned char *expected,
                           size_t expected_length,
                           const unsigned char *data, size_t data_length);
enum storage_atomic_result storage_atomic_replace_result(
    const struct storage *storage, enum storage_area area,
    const char *filename, const unsigned char *expected,
    size_t expected_length, const unsigned char *data, size_t data_length);

int storage_append_file(const struct storage *storage, enum storage_area area,
                        const char *filename,
                        const unsigned char *data, size_t data_length,
                        size_t maximum_size);
int storage_remove_file(const struct storage *storage, enum storage_area area,
                        const char *filename);

int storage_lock_acquire(const struct storage *storage, enum storage_area area,
                         const char *filename, struct storage_lock *lock);
int storage_lock_is_held(const struct storage_lock *lock);
int storage_lock_validate(const struct storage *storage,
                          enum storage_area area, const char *filename,
                          const struct storage_lock *lock);
void storage_lock_release(struct storage_lock *lock);

#endif
