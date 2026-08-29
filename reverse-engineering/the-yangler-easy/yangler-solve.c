#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

const unsigned char sub[] = "\xec\x94\x9e\xbdJ?n'@\xb5jc\x7fR\xf0^W\x19#\x80\xd4";
const uint8_t goal[22] = 
{
	0x55, 0x17, 0x04, 0xbc, 0x67, 
    0x05, 0xc9, 0xeb, 0x46, 0x9d,
    0xa1, 0xb8, 0x91, 0x3d, 0x0f, 
    0xb3, 0x52, 0x5a, 0x0d, 0x1f, 
    0xb0
};

int main(void) 
{
    for (size_t i = 0; i < sizeof goal -1; i++)
    {
        unsigned char ch = (goal[i] - sub[i]) & 0xFF;
        //printf("%u\n", ch);
        write(STDOUT_FILENO, &ch, 1);
    }
}
