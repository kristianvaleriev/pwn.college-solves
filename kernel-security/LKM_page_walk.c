#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <asm/pgtable.h>
#include <asm/current.h>

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

static ssize_t debug_device_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	char *msg = "Hello pwn-college!\n";
	return copy_to_user(buffer, msg, strlen(msg)) ? -EFAULT : 0;
}

static char my_buf[128] = {0};
#define userspace_addr 0x404040
//#define userspace_addr 0x402000
//#define userspace_addr 0xffffffff88c07da8

#define PHYSMEM_START 0xffff888000000000

static ssize_t debug_device_write(struct file *filp, const char *buf, 
                                  size_t len, loff_t *off)
{
 	void*  cont = current->children.next;
	struct task_struct* child = container_of(cont, struct task_struct, sibling);
/*
    p4d_t *pgd = p4d_offset(current->mm->pgd, userspace_addr);
    pud_t *pud = pud_offset(pgd, userspace_addr);
    pmd_t *pmd = pmd_offset(pud, userspace_addr);
    pte_t *pte = pte_offset_map(pmd, userspace_addr);
	pr_info("g: %#px, u:%#px, m:%#px, t:%#px ", pgd, pud, pmd, pte);
	pr_info("g: %#px, u:%#px, m:%#px, t:%#px ", *pgd, *pud, *pmd, *pte);

	struct page *page = pte_page(*pte);
	pr_info(" pte: %#px\n", pte);
	pr_info("*pte: %#px\n", *pte);
	pr_info("page: %#px\n", page);
	pr_info("*page: %#px\n", *page);
*/

	ssize_t offsets[4], i, addr = userspace_addr >> 12;
	for (i = 0; i < 4; i++) 
	{
		offsets[i] = (addr >> (9 * i)) & 0x1ff;
		pr_info("offsets[%zu] = %zu\n", i, offsets[i]);
	}
    
 	size_t walk = (size_t)child->mm->pgd;
	pr_info("pgd: %#px\n", walk);

	for (i = 3; i >= 0; i--) 
	{
		walk  = (*(size_t*)((walk & ~0xfff) + offsets[i] * 8));
		walk &= ~((1<<12)-1) & ((1ull<<51) - 1);
		pr_info("walk[%d] = %#px\n", i, walk);
		walk += PHYSMEM_START;
	}

	asm volatile(
		"movq $0xffffffff810bc8e0, %rax\n"
    	"call %rax\n"
	);

	printk(KERN_ALERT "RETURNING...\n");
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

