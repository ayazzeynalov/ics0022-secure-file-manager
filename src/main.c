#include <stdio.h>
#include <string.h>

#define SECUREPM_VERSION "0.1.0-checkpoint1"

static void print_usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Secure Password Manager (%s)\n"
            "ICS0022 Secure Programming project\n\n"
            "Usage:\n"
            "  %s\n"
            "  %s --help\n\n"
            "Planned interactive flow:\n"
            "  1. Create user\n"
            "  2. Login\n"
            "  3. Exit\n\n"
            "After login, planned commands are:\n"
            "  add\n"
            "  list\n"
            "  show <record-id>\n"
            "  copy <record-id>\n"
            "  update <record-id>\n"
            "  delete <record-id>\n"
            "  lock\n"
            "  help\n"
            "  exit\n\n"
            "Checkpoint 1 status:\n"
            "  Architecture, threat model, vault format, and command interface\n"
            "  are defined. Authentication and encrypted vault functionality\n"
            "  are intentionally planned for Checkpoint 2.\n",
            SECUREPM_VERSION,
            program,
            program);
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        print_usage(stdout, argv[0]);
        return 0;
    }

    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_usage(stdout, argv[0]);
        return 0;
    }

    fprintf(stderr,
            "securepm: Checkpoint 1 contains only the CLI skeleton.\n"
            "Run '%s --help' to view the planned interface.\n",
            argv[0]);
    return 2;
}
