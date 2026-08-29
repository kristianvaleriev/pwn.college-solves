#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

const unsigned char sub[] = "a9\\\xcb\x17o\xb9""dg2\x8d\xfc\xefu";

const uint8_t goal[] = 
{
	0xeb, 0x80, 0x35, 0xc1, 
    0x3e, 0xce, 0x52, 0xa3, 0x5b, 0x85,
	0x09, 0xa0, 0x24, 0x6c
};

int main(void) 
{
    for (size_t i = 0; i < sizeof goal; i++)
    {
        unsigned char ch = (goal[i] - sub[i]) & 0xFF;
        //printf("%u\n", ch);
        write(STDOUT_FILENO, &ch, 1);
    }
}
