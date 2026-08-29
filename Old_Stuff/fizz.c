#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "process.h"

int main(int argc, char** argv)
{
    struct stack_vars sv = {1};
    memset(&sv, 0x11, sizeof sv);
    sv.__pad2 = 0x22222222;
    sv.iter_idx = 0x1010;

//    printf("%p %p\n", &sv.__pad2, &sv.iter_idx);

    char buf[DEF_COUNT] = {0};

    if (argc < 2) {
        fputs("Usage: ./prog [BIN]\n", stderr);
        exit(1);
    }

    int proc_fd = process(argv[1]);
    if (proc_fd < 0) {
        perror("process:");
        exit(1);
    }

    proc_write(&sv, sizeof sv);
    while (pread(buf))
        printf("%s\n", buf);
}
