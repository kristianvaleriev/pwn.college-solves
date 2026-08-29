#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

const char goal[] = "\x07&\x05\"\r/+*\x08\n\x16""4\x17""7\x13""3\x11";

int main(void)
{
    char* payload = malloc(sizeof goal);
    memcpy(payload, goal, sizeof goal);

    char temp = payload[6];
    payload[6] = payload[9];
    payload[9] = temp;

    // mangled XOR
    for (size_t i = 0; i < sizeof goal-1; i++) 
    {
        if (i % 2) 
            payload[i] ^= 0x44;     
        else 
            payload[i] ^= 0x66;
    }

    // mangled SORT
    for (size_t i = 0; i < sizeof goal-1; i++) 
    {
        ;
    }

    write(STDOUT_FILENO, payload, sizeof goal-1);
}


