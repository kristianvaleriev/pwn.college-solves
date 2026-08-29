#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>

#include "process.h"

int proc_out[2];
int proc_in[2];

int process(char* filename)
{
    pipe(proc_out);
    pipe(proc_in);

    pid_t pid = fork();
    if (pid) {
        close(proc_out[1]);
        close(proc_in[0]);
        sleep(1);

        return pid;
    }

    close(proc_out[0]);
    close(proc_in[1]);

    if (dup2(proc_out[1], STDOUT_FILENO) != STDOUT_FILENO ||
        dup2(proc_out[1], STDERR_FILENO) != STDERR_FILENO ||
        dup2(proc_in[0], STDIN_FILENO) != STDIN_FILENO) {
        perror("dup2 in process failed: ");
        exit(1);
    }

    execl(filename, NULL);
    perror("execl failed in process: ");
    exit(2);
}

char* proc_read(char* buf, size_t count)
{
    if (read(proc_out[0], buf, count) < 0)
        return NULL;
    return buf;
}

int readuntil(char* str)
{
    char ch;
    size_t i=0, len = strlen(str);
    
    while (read(proc_out[0], &ch, 1)) 
    {
        if (ch == str[i++]) {
            if (i == len)
                return 1;
            continue;
        }
        i = 0;
    }
    return 0;
}

char* readline(char* buf, size_t count)
{
    char ch;
    size_t idx = 0;
    while (read(proc_out[0], &ch, 1)) {
        if (ch == '\n' || idx >= count)
            break;
        buf[idx++] = ch;
    }

    return buf;
}

int proc_write(void* buf, size_t count) 
{
    return write(proc_in[1], buf, count);
}
