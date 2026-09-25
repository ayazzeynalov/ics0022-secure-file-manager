#include <stdio.h>
#include <string.h>

static void print_help(const char *program)
{
    printf("Secure Password Manager - Checkpoint 1\n\n");
    printf("Usage:\n");
    printf("  %s\n", program);
    printf("  %s --help\n\n", program);

    printf("Planned commands after login:\n");
    printf("  add\n");
    printf("  list\n");
    printf("  show <record-id>\n");
    printf("  copy <record-id>\n");
    printf("  update <record-id>\n");
    printf("  delete <record-id>\n");
    printf("  lock\n");
    printf("  help\n");
    printf("  exit\n");
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        print_help(argv[0]);
        return 0;
    }

    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_help(argv[0]);
        return 0;
    }

    fprintf(stderr, "Unknown option. Use --help.\n");
    return 1;
}
