#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const unsigned char goal[] = "\x7b\x31\xcb\xbe\x9d\x6b\x44\x09\x43\x35\x7f\xa4";
const unsigned char sub [] = "\xb7\x21\x70\x10\xff\xe3\x6e\xbf\x4b\xf2\x7a\x71";

int main(void) 
{
    printf("%zu\n", sizeof goal-1);
    for (size_t i = 0; i < sizeof goal -1; i++)
    {
        unsigned char ch = (goal[i] - sub[i]) & 0xFF;
        //printf("%u\n", ch);
        write(STDOUT_FILENO, &ch, 1);
    }
}
