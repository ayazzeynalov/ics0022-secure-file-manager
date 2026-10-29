#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "cli.h"

#include "account.h"
#include "credentials.h"
#include "input.h"
#include "storage.h"
#include "vault.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>

#define MENU_INPUT_BYTES 16
#define LOGIN_DELAY_BASE_MILLISECONDS 500U
#define LOGIN_DELAY_MAX_FAILURES 3U

#define ACTION_CONTINUE 0
#define ACTION_EXIT 1
#define ACTION_INPUT_END 2

struct login_throttle {
    unsigned int failures;
};

static void throttle_login_failure(struct login_throttle *throttle,
                                   const struct timespec *attempt_start)
{
    struct timespec now;
    struct timespec delay;
    int64_t remaining_nanoseconds;
    unsigned int delay_milliseconds;

    if (throttle == NULL) {
        return;
    }
    if (throttle->failures < LOGIN_DELAY_MAX_FAILURES) {
        ++throttle->failures;
    }
    delay_milliseconds = LOGIN_DELAY_BASE_MILLISECONDS <<
                         (throttle->failures - 1);
    remaining_nanoseconds = (int64_t)delay_milliseconds * 1000000;
    if (attempt_start != NULL &&
        clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        remaining_nanoseconds -=
            (int64_t)(now.tv_sec - attempt_start->tv_sec) * 1000000000 +
            (int64_t)now.tv_nsec - attempt_start->tv_nsec;
    }
    if (remaining_nanoseconds <= 0) {
        return;
    }
    delay.tv_sec = (time_t)(remaining_nanoseconds / 1000000000);
    delay.tv_nsec = (long)(remaining_nanoseconds % 1000000000);
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR &&
           input_interrupted_signal() == 0) {
    }
}

static void print_help(const char *program)
{
    printf("Secure Password Manager\n\n");
    printf("Usage:\n");
    printf("  %s\n", program);
    printf("  %s --help\n\n", program);
    printf("Run without arguments in a terminal to create a user, log in, ");
    printf("add, view, update, delete, or list credentials.\n");
    printf("Passwords are read interactively and are never accepted as ");
    printf("command-line arguments.\n");
}

static int read_value(const char *prompt, char *buffer, size_t capacity,
                      size_t *length, int secret)
{
    int result = secret ? input_read_secret(prompt, buffer, capacity, length) :
                          input_read_line(prompt, buffer, capacity, length);

    if (result == INPUT_READ_OK) {
        return 1;
    }
    if (result == INPUT_READ_TOO_LONG) {
        puts("Input too long.");
        return 0;
    }
    if (result == INPUT_READ_INVALID) {
        puts("Invalid input.");
        return 0;
    }
    return -1;
}

static int serialize_and_write(const struct storage *storage,
                               const struct account_session *session,
                               const struct credential_collection *collection)
{
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    int success = 0;

    if (session == NULL || session->unlocked != 1 ||
        !credentials_serialize(collection, &payload, &payload_length)) {
        goto cleanup;
    }
    success = vault_write(storage, session, payload, payload_length);

cleanup:
    credentials_serialized_free(payload, payload_length);
    return success;
}

static int save_updated_collection(
    const struct storage *storage, const struct account_session *session,
    struct credential_collection *collection,
    const struct credential_collection *updated)
{
    if (!serialize_and_write(storage, session, updated)) {
        return 0;
    }
    credentials_cleanup(collection);
    memcpy(collection, updated, sizeof(*collection));
    return 1;
}

static int register_user(const struct storage *storage)
{
    char username[USER_DB_USERNAME_MAX_BYTES + 1];
    char password[CRYPTO_PASSWORD_MAX_BYTES + 1];
    char confirmation[CRYPTO_PASSWORD_MAX_BYTES + 1];
    struct account_session session = ACCOUNT_SESSION_INITIALIZER;
    struct storage_lock vault_lock = STORAGE_LOCK_INITIALIZER;
    struct credential_collection *empty = NULL;
    unsigned char *existing_payload = NULL;
    size_t username_length = 0;
    size_t password_length = 0;
    size_t confirmation_length = 0;
    size_t existing_payload_length = 0;
    int read_result;
    int registration_result;
    int vault_result;
    int action = ACTION_CONTINUE;

    memset(password, 0, sizeof(password));
    memset(confirmation, 0, sizeof(confirmation));
    read_result = read_value("Username: ", username, sizeof(username),
                             &username_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("Master password: ", password, sizeof(password),
                             &password_length, 1);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("Confirm master password: ", confirmation,
                             sizeof(confirmation), &confirmation_length, 1);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    if (password_length != confirmation_length ||
        CRYPTO_memcmp(password, confirmation, password_length) != 0) {
        puts("Master passwords do not match.");
        goto cleanup;
    }
    OPENSSL_cleanse(confirmation, sizeof(confirmation));
    confirmation_length = 0;
    registration_result = account_register(storage, username, username_length,
                                           password, password_length);
    if (registration_result == ACCOUNT_REGISTER_ERROR) {
        puts("Registration failed.");
        goto cleanup;
    }
    empty = malloc(sizeof(*empty));
    if (empty != NULL) {
        credentials_init(empty);
    }
    if (empty == NULL ||
        !account_unlock(storage, username, username_length,
                        password, password_length, &session) ||
        !vault_lock_acquire(storage, &session, &vault_lock)) {
        puts("Account metadata was created, but encrypted vault "
             "initialization failed. Registration is incomplete.");
        goto cleanup;
    }
    vault_result = vault_read(storage, &session,
                              &existing_payload, &existing_payload_length);
    if ((vault_result == VAULT_READ_MISSING &&
         !serialize_and_write(storage, &session, empty)) ||
        (vault_result == VAULT_READ_OK &&
         !credentials_deserialize(existing_payload,
                                  existing_payload_length, empty)) ||
        vault_result == VAULT_READ_ERROR ||
        !account_registration_complete(storage, &session)) {
        puts("Account metadata was created, but encrypted vault "
             "initialization failed. Registration is incomplete.");
        goto cleanup;
    }
    puts("User created.");

cleanup:
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(confirmation, sizeof(confirmation));
    OPENSSL_cleanse(username, sizeof(username));
    vault_secure_free(existing_payload, existing_payload_length);
    if (empty != NULL) {
        credentials_cleanup(empty);
        free(empty);
    }
    account_session_lock(&session);
    storage_lock_release(&vault_lock);
    return action;
}

static void print_record_id(
    const unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES])
{
    static const char hexadecimal[] = "0123456789abcdef";

    for (size_t index = 0; index < CREDENTIALS_RECORD_ID_BYTES; ++index) {
        putchar(hexadecimal[record_id[index] >> 4]);
        putchar(hexadecimal[record_id[index] & 0x0f]);
    }
}

static void print_safe_field(const unsigned char *field, size_t length)
{
    static const char hexadecimal[] = "0123456789abcdef";

    if (length == 0) {
        fputs("(empty)", stdout);
        return;
    }
    for (size_t index = 0; index < length; ++index) {
        unsigned char byte = field[index];

        if (byte >= 0x20 && byte <= 0x7e && byte != '\\') {
            putchar(byte);
        } else {
            fputs("\\x", stdout);
            putchar(hexadecimal[byte >> 4]);
            putchar(hexadecimal[byte & 0x0f]);
        }
    }
}

static int hexadecimal_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int read_record_id(unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES])
{
    char encoded[CREDENTIALS_RECORD_ID_BYTES * 2 + 1];
    size_t encoded_length = 0;
    int read_result = read_value("Record ID: ", encoded, sizeof(encoded),
                                 &encoded_length, 0);

    if (read_result <= 0) {
        OPENSSL_cleanse(encoded, sizeof(encoded));
        return read_result;
    }
    if (encoded_length != CREDENTIALS_RECORD_ID_BYTES * 2) {
        puts("Invalid record ID.");
        OPENSSL_cleanse(encoded, sizeof(encoded));
        return 0;
    }
    for (size_t index = 0; index < CREDENTIALS_RECORD_ID_BYTES; ++index) {
        int high = hexadecimal_value(encoded[index * 2]);
        int low = hexadecimal_value(encoded[index * 2 + 1]);

        if (high < 0 || low < 0) {
            puts("Invalid record ID.");
            OPENSSL_cleanse(record_id, CREDENTIALS_RECORD_ID_BYTES);
            OPENSSL_cleanse(encoded, sizeof(encoded));
            return 0;
        }
        record_id[index] = (unsigned char)((high << 4) | low);
    }
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return 1;
}

static void list_credentials(const struct account_session *session,
                             const struct credential_collection *collection)
{
    if (session == NULL || session->unlocked != 1 || collection == NULL) {
        puts("Vault is locked.");
        return;
    }
    if (collection->count == 0) {
        puts("No credentials.");
        return;
    }
    for (size_t index = 0; index < collection->count; ++index) {
        const struct credential_record *record = &collection->records[index];

        printf("%zu. ID: ", index + 1);
        print_record_id(record->id);
        fputs(" | Label: ", stdout);
        print_safe_field(record->label, record->label_length);
        fputs(" | Username: ", stdout);
        print_safe_field(record->username, record->username_length);
        putchar('\n');
    }
}

static int view_credential(const struct account_session *session,
                           const struct credential_collection *collection)
{
    unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    char confirmation[8] = {0};
    const struct credential_record *record;
    size_t confirmation_length = 0;
    int read_result;
    int action = ACTION_CONTINUE;

    if (session == NULL || session->unlocked != 1 || collection == NULL) {
        puts("Vault is locked.");
        return action;
    }
    read_result = read_record_id(record_id);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    record = credentials_find(collection, record_id, sizeof(record_id));
    if (record == NULL) {
        puts("Credential not found.");
        goto cleanup;
    }
    fputs("ID: ", stdout);
    print_record_id(record->id);
    fputs("\nLabel: ", stdout);
    print_safe_field(record->label, record->label_length);
    fputs("\nUsername: ", stdout);
    print_safe_field(record->username, record->username_length);
    fputs("\nNotes: ", stdout);
    print_safe_field(record->notes, record->notes_length);
    fputs("\nPassword: hidden\n", stdout);
    puts("Warning: revealed passwords may remain visible in terminal output.");
    read_result = read_value("Type yes to reveal password: ", confirmation,
                             sizeof(confirmation), &confirmation_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    if (confirmation_length != 3 ||
        memcmp(confirmation, "yes", 3) != 0) {
        puts("Password remains hidden.");
        goto cleanup;
    }
    fputs("Password: ", stdout);
    print_safe_field(record->password, record->password_length);
    putchar('\n');

cleanup:
    OPENSSL_cleanse(record_id, sizeof(record_id));
    OPENSSL_cleanse(confirmation, sizeof(confirmation));
    return action;
}

static int add_credential(const struct storage *storage,
                          const struct account_session *session,
                          struct credential_collection *collection)
{
    char label[CREDENTIALS_LABEL_MAX_BYTES + 1];
    char username[CREDENTIALS_USERNAME_MAX_BYTES + 1];
    char password[CREDENTIALS_PASSWORD_MAX_BYTES + 1];
    char notes[CREDENTIALS_NOTES_MAX_BYTES + 1];
    unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    struct credential_collection *updated = NULL;
    size_t label_length = 0;
    size_t username_length = 0;
    size_t password_length = 0;
    size_t notes_length = 0;
    int read_result;
    int action = ACTION_CONTINUE;

    memset(password, 0, sizeof(password));
    if (session == NULL || session->unlocked != 1) {
        puts("Vault is locked.");
        goto cleanup;
    }
    read_result = read_value("Label: ", label, sizeof(label),
                             &label_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("Credential username: ", username,
                             sizeof(username), &username_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("Credential password: ", password,
                             sizeof(password), &password_length, 1);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("Notes (optional): ", notes, sizeof(notes),
                             &notes_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    updated = malloc(sizeof(*updated));
    if (updated == NULL) {
        puts("Credential could not be saved.");
        goto cleanup;
    }
    memcpy(updated, collection, sizeof(*updated));
    if (!credentials_add(updated,
                         (const unsigned char *)label, label_length,
                         (const unsigned char *)username, username_length,
                         (const unsigned char *)password, password_length,
                         (const unsigned char *)notes, notes_length,
                         record_id)) {
        puts("Credential could not be saved.");
        goto cleanup;
    }
    OPENSSL_cleanse(password, sizeof(password));
    password_length = 0;
    if (!save_updated_collection(storage, session, collection, updated)) {
        puts("Credential could not be saved.");
        goto cleanup;
    }
    puts("Credential added.");

cleanup:
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(record_id, sizeof(record_id));
    OPENSSL_cleanse(label, sizeof(label));
    OPENSSL_cleanse(username, sizeof(username));
    OPENSSL_cleanse(notes, sizeof(notes));
    if (updated != NULL) {
        credentials_cleanup(updated);
        free(updated);
    }
    return action;
}

static int update_credential(const struct storage *storage,
                             const struct account_session *session,
                             struct credential_collection *collection)
{
    unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    char label[CREDENTIALS_LABEL_MAX_BYTES + 1];
    char username[CREDENTIALS_USERNAME_MAX_BYTES + 1];
    char password[CREDENTIALS_PASSWORD_MAX_BYTES + 1];
    char notes[CREDENTIALS_NOTES_MAX_BYTES + 1];
    struct credential_collection *updated = NULL;
    size_t label_length = 0;
    size_t username_length = 0;
    size_t password_length = 0;
    size_t notes_length = 0;
    int read_result;
    int action = ACTION_CONTINUE;

    memset(password, 0, sizeof(password));
    if (session == NULL || session->unlocked != 1) {
        puts("Vault is locked.");
        goto cleanup;
    }
    read_result = read_record_id(record_id);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    if (credentials_find(collection, record_id, sizeof(record_id)) == NULL) {
        puts("Credential not found.");
        goto cleanup;
    }
    read_result = read_value("New label: ", label, sizeof(label),
                             &label_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("New credential username: ", username,
                             sizeof(username), &username_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("New credential password: ", password,
                             sizeof(password), &password_length, 1);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("New notes (optional): ", notes, sizeof(notes),
                             &notes_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    updated = malloc(sizeof(*updated));
    if (updated == NULL) {
        puts("Credential could not be updated.");
        goto cleanup;
    }
    memcpy(updated, collection, sizeof(*updated));
    if (!credentials_update(updated, record_id, sizeof(record_id),
                            (const unsigned char *)label, label_length,
                            (const unsigned char *)username, username_length,
                            (const unsigned char *)password, password_length,
                            (const unsigned char *)notes, notes_length)) {
        puts("Credential could not be updated.");
        goto cleanup;
    }
    OPENSSL_cleanse(password, sizeof(password));
    password_length = 0;
    if (!save_updated_collection(storage, session, collection, updated)) {
        puts("Credential could not be updated.");
        goto cleanup;
    }
    puts("Credential updated.");

cleanup:
    OPENSSL_cleanse(record_id, sizeof(record_id));
    OPENSSL_cleanse(label, sizeof(label));
    OPENSSL_cleanse(username, sizeof(username));
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(notes, sizeof(notes));
    if (updated != NULL) {
        credentials_cleanup(updated);
        free(updated);
    }
    return action;
}

static int delete_credential(const struct storage *storage,
                             const struct account_session *session,
                             struct credential_collection *collection)
{
    unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    char confirmation[8];
    struct credential_collection *updated = NULL;
    size_t confirmation_length = 0;
    int read_result;
    int action = ACTION_CONTINUE;

    if (session == NULL || session->unlocked != 1) {
        puts("Vault is locked.");
        goto cleanup;
    }
    read_result = read_record_id(record_id);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    if (credentials_find(collection, record_id, sizeof(record_id)) == NULL) {
        puts("Credential not found.");
        goto cleanup;
    }
    read_result = read_value("Type yes to confirm deletion: ", confirmation,
                             sizeof(confirmation), &confirmation_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    if (confirmation_length != 3 ||
        memcmp(confirmation, "yes", 3) != 0) {
        puts("Deletion cancelled.");
        goto cleanup;
    }
    updated = malloc(sizeof(*updated));
    if (updated == NULL) {
        puts("Credential could not be deleted.");
        goto cleanup;
    }
    memcpy(updated, collection, sizeof(*updated));
    if (!credentials_delete(updated, record_id, sizeof(record_id)) ||
        !save_updated_collection(storage, session, collection, updated)) {
        puts("Credential could not be deleted.");
        goto cleanup;
    }
    puts("Credential deleted.");

cleanup:
    OPENSSL_cleanse(record_id, sizeof(record_id));
    OPENSSL_cleanse(confirmation, sizeof(confirmation));
    if (updated != NULL) {
        credentials_cleanup(updated);
        free(updated);
    }
    return action;
}

static int authenticated_menu(
    const struct storage *storage, struct account_session *session,
    struct credential_collection *collection)
{
    char choice[MENU_INPUT_BYTES];
    size_t choice_length;

    while (session->unlocked == 1) {
        int read_result;

        puts("\nVault menu:");
        puts("1. Add credential");
        puts("2. List credentials");
        puts("3. View credential details");
        puts("4. Update credential");
        puts("5. Delete credential");
        puts("6. Lock");
        puts("7. Exit");
        read_result = read_value("Choice: ", choice, sizeof(choice),
                                 &choice_length, 0);
        if (read_result < 0) {
            return ACTION_INPUT_END;
        }
        if (read_result == 0) {
            continue;
        }
        if (choice_length == 1 && choice[0] == '1') {
            if (add_credential(storage, session, collection) ==
                ACTION_INPUT_END) {
                return ACTION_INPUT_END;
            }
        } else if (choice_length == 1 && choice[0] == '2') {
            list_credentials(session, collection);
        } else if (choice_length == 1 && choice[0] == '3') {
            if (view_credential(session, collection) == ACTION_INPUT_END) {
                return ACTION_INPUT_END;
            }
        } else if (choice_length == 1 && choice[0] == '4') {
            if (update_credential(storage, session, collection) ==
                ACTION_INPUT_END) {
                return ACTION_INPUT_END;
            }
        } else if (choice_length == 1 && choice[0] == '5') {
            if (delete_credential(storage, session, collection) ==
                ACTION_INPUT_END) {
                return ACTION_INPUT_END;
            }
        } else if (choice_length == 1 && choice[0] == '6') {
            account_session_lock(session);
            credentials_cleanup(collection);
            puts("Vault locked.");
            return ACTION_CONTINUE;
        } else if (choice_length == 1 && choice[0] == '7') {
            return ACTION_EXIT;
        } else {
            puts("Invalid choice.");
        }
    }
    return ACTION_CONTINUE;
}

static int login_user(const struct storage *storage,
                      struct login_throttle *throttle)
{
    char username[USER_DB_USERNAME_MAX_BYTES + 1];
    char password[CRYPTO_PASSWORD_MAX_BYTES + 1];
    struct account_session session = ACCOUNT_SESSION_INITIALIZER;
    struct storage_lock vault_lock = STORAGE_LOCK_INITIALIZER;
    struct credential_collection *collection = NULL;
    unsigned char *payload = NULL;
    size_t username_length = 0;
    size_t password_length = 0;
    size_t payload_length = 0;
    int read_result;
    int action = ACTION_CONTINUE;
    struct timespec attempt_start;
    int have_attempt_start = 0;

    memset(password, 0, sizeof(password));
    read_result = read_value("Username: ", username, sizeof(username),
                             &username_length, 0);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    read_result = read_value("Master password: ", password, sizeof(password),
                             &password_length, 1);
    if (read_result <= 0) {
        action = read_result < 0 ? ACTION_INPUT_END : ACTION_CONTINUE;
        goto cleanup;
    }
    have_attempt_start = clock_gettime(CLOCK_MONOTONIC, &attempt_start) == 0;
    if (!account_unlock(storage, username, username_length,
                        password, password_length, &session)) {
        throttle_login_failure(throttle,
                               have_attempt_start ? &attempt_start : NULL);
        puts("Login failed.");
        goto cleanup;
    }
    if (throttle != NULL) {
        throttle->failures = 0;
    }
    OPENSSL_cleanse(password, sizeof(password));
    password_length = 0;
    if (!vault_lock_acquire(storage, &session, &vault_lock) ||
        vault_read(storage, &session, &payload, &payload_length) !=
        VAULT_READ_OK) {
        puts("Login failed.");
        goto cleanup;
    }
    collection = malloc(sizeof(*collection));
    if (collection == NULL) {
        puts("Login failed.");
        goto cleanup;
    }
    credentials_init(collection);
    if (!credentials_deserialize(payload, payload_length, collection)) {
        puts("Login failed.");
        goto cleanup;
    }
    vault_secure_free(payload, payload_length);
    payload = NULL;
    payload_length = 0;
    puts("Login successful.");
    action = authenticated_menu(storage, &session, collection);

cleanup:
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(username, sizeof(username));
    vault_secure_free(payload, payload_length);
    if (collection != NULL) {
        credentials_cleanup(collection);
        free(collection);
    }
    account_session_lock(&session);
    storage_lock_release(&vault_lock);
    return action;
}

static int interactive_run(void)
{
    struct storage storage = STORAGE_INITIALIZER;
    struct login_throttle throttle = {0};
    char choice[MENU_INPUT_BYTES];
    size_t choice_length;
    int exit_status = 0;

    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fputs("Interactive terminal required.\n", stderr);
        return 1;
    }
    if (!input_initialize()) {
        fputs("Could not initialize terminal input.\n", stderr);
        return 1;
    }
    if (!storage_init(&storage)) {
        fputs("Could not initialize secure storage.\n", stderr);
        return 1;
    }
    while (1) {
        int read_result;
        int action = ACTION_CONTINUE;

        puts("\nSecure Password Manager:");
        puts("1. Create user");
        puts("2. Login");
        puts("3. Exit");
        read_result = read_value("Choice: ", choice, sizeof(choice),
                                 &choice_length, 0);
        if (read_result < 0) {
            break;
        }
        if (read_result == 0) {
            continue;
        }
        if (choice_length == 1 && choice[0] == '1') {
            action = register_user(&storage);
        } else if (choice_length == 1 && choice[0] == '2') {
            action = login_user(&storage, &throttle);
        } else if (choice_length == 1 && choice[0] == '3') {
            break;
        } else {
            puts("Invalid choice.");
        }
        if (action == ACTION_EXIT || action == ACTION_INPUT_END) {
            break;
        }
    }
    storage_close(&storage);
    input_cleanup();
    if (input_interrupted_signal() != 0) {
        exit_status = 128 + input_interrupted_signal();
    }
    return exit_status;
}

int cli_run(int argc, char *argv[])
{
    if (argc == 1) {
        return interactive_run();
    }
    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_help(argv[0]);
        return 0;
    }
    fprintf(stderr, "Unknown option. Use --help.\n");
    return 1;
}
