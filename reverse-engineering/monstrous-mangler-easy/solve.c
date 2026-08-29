#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

const char goal[] = "@AL\x8eOYY^_\x81\x82\x86\x8b\x8b\x8b\x8c\x8cL\x8f\x8f\x92\x93\x95\x97\x98\x99\x9e\xe7\xe9\xed\xef\xf0\xf4\xf8\xf9\xfa";

void swap(char* arr, size_t idx1, size_t idx2)
{
    char temp = arr[idx1];
    arr[idx1] = arr[idx2];
    arr[idx2] = temp;
}

int main(void)
{
    char* payload = malloc(sizeof goal);
    memcpy(payload, goal, sizeof goal);

    swap(payload, 3, 17);

    // reverse
    for (size_t i = 0; i < (sizeof goal - 1) / 2; i++)
        swap(payload, i, sizeof goal -2 - i);


    for (size_t i = 0; i < (sizeof goal -1); i++)
    {
        if (i % 4 == 3) 
            payload[i] ^= 0x9f;
        else if (i % 4 == 2) 
            payload[i] ^= 0x35;
        else if (i % 4 == 1) 
            payload[i] ^= 0xf6;
        else if (i % 4 == 0) 
            payload[i] ^= 0xf8;

    }

    swap(payload, 17, 23);

    for (size_t i = 0; i < (sizeof goal - 1) / 2; i++)
        swap(payload, i, sizeof goal -2 - i);

    swap(payload, 12, 32);



    write(STDOUT_FILENO, payload, sizeof goal-1);
}


