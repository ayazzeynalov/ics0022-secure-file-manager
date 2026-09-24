#include <stdio.h>
#include <string.h>

#define SECUREFM_VERSION "0.1.0-checkpoint1"

static void print_usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Secure File Manager (%s)\n"
            "ICS0022 Secure Programming project\n\n"
            "Usage:\n"
            "  %s init\n"
            "  %s create-user <username>\n"
            "  %s encrypt <username> <source-path> <alias>\n"
            "  %s decrypt <username> <alias> <output-path>\n"
            "  %s list <username>\n"
            "  %s delete <username> <alias>\n"
            "  %s --help\n\n"
            "Checkpoint 1 status:\n"
            "  The command interface is defined, but authentication, encryption,\n"
            "  storage, and deletion are intentionally not implemented yet.\n"
            "  See docs/checkpoint1-design.md for the security architecture.\n",
            SECUREFM_VERSION,
            program,
            program,
            program,
            program,
            program,
            program,
            program);
}

int main(int argc, char *argv[])
{
    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_usage(stdout, argv[0]);
        return 0;
    }

    if (argc == 1) {
        print_usage(stdout, argv[0]);
        return 0;
    }

    fprintf(stderr,
            "securefm: command not implemented in Checkpoint 1.\n"
            "Run '%s --help' to see the planned interface.\n",
            argv[0]);
    return 2;
}
