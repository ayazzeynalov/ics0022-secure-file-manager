#include "cli.h"

#include <stdio.h>
#include <sys/resource.h>

int main(int argc, char *argv[])
{
    const struct rlimit no_core = {0, 0};

    /* Disable ordinary core dumps before handling secrets. */
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
        fputs("Could not disable core dumps.\n", stderr);
        return 1;
    }
    return cli_run(argc, argv);
}
