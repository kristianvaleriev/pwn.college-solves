#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const unsigned char goal[] = "\x5a\xc3\x03\x64\x31\x01\xdd\x9a\x1b";
const unsigned char sub [] = "\x35\xd6\x65\xc0\xcb\x38\xd5\x3a\x6f";

int main(void) 
{
    for (size_t i = 0; i < sizeof goal -1; i++)
    {
        unsigned char ch = (goal[i] - sub[i]) & 0xFF;
        //printf("%u\n", ch);
        write(STDOUT_FILENO, &ch, 1);
    }
}
