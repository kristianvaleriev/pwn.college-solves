#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

const char goal[] = "\xa0\xac\xb4\xb5\xb7\xb7\xc1\xc1\xc6\xcb\xd9\xdc\xe3\xe5\xe7\xe8\xeb\xfb";

int main(void)
{
    char* payload = malloc(sizeof goal);
    memcpy(payload, goal, sizeof goal);

    for (size_t i = 0; i < (sizeof goal -1) / 2; i++)
    {
        char temp = payload[i];
        payload[i] = payload[sizeof goal - 2 - i];
        payload[sizeof goal - 2 - i] = temp;
    }

    for (size_t i = 0; i < sizeof goal -1; i++)
    {
        if (i % 3 == 2) 
            payload[i] ^= 0xAD;
        else if (i % 3 == 0)
            payload[i] ^= 0xDA;
        else if (i % 3 == 1)
            payload[i] ^= 0x92;
    }

    write(STDOUT_FILENO, payload, sizeof goal-1);
}


