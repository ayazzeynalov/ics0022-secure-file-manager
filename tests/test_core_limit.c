/* Linked with the real main.c to observe limits at the CLI entry point. */
#include "cli.h"
#include <stdio.h>
#include <sys/resource.h>

int cli_run(int argc, char *argv[])
{
    struct rlimit limit;
    (void)argc;
    (void)argv;
    if (getrlimit(RLIMIT_CORE, &limit) != 0 ||
        limit.rlim_cur != 0 || limit.rlim_max != 0) {
        fputs("FAIL: core limits not disabled\n", stderr);
        return 1;
    }
    puts("PASS: soft and hard core limits are zero before CLI entry");
    return 0;
}
