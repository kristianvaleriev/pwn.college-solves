#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const unsigned char goal[] = "\x6a\x24\x33\x14\xca\x8e\xc3\xdd\x06\x44\xae\x57";
const unsigned char sub [] = "\x48\x29\xcc\x46\x93\xc4\x8c\x38\x04\xb3\xb0\x09";

int main(void) 
{
    for (size_t i = 0; i < sizeof goal -1; i++)
    {
        unsigned char ch = (goal[i] + sub[i]) & 0xFF;
        //printf("%u\n", ch);
        write(STDOUT_FILENO, &ch, 1);
    }
}
