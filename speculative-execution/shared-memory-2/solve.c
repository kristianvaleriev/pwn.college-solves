#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <semaphore.h>

int main(void)
{
    sem_post((sem_t*)0x1337000);
    printf("%s\n", (char*) 0x1337024);
}
