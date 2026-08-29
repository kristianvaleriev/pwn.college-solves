#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const unsigned char goal[] = "\x77\x3b\xdc\xd6\x9a\x37";
const unsigned char sub [] = "\x3c\x14\x15\x0f\x4f\x40";

int main(void) 
{
    for (size_t i = 0; i < sizeof goal -1; i++)
    {
        unsigned char ch = (goal[i] - sub[i]) & 0xFF;
        //printf("%u\n", ch);
        write(STDOUT_FILENO, &ch, 1);
    }
}
