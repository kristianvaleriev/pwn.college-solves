#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void)
{
    printf("%s\n", (char*) 0x1337024);
}
