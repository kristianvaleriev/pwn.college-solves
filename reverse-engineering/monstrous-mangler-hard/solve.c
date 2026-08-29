#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

const char goal[] = "\n\xfa\x87""A/{!\x1a\xe5\x8b""C@h;\x08\xe6\x86GLi%\x17\xe0\x81UAi<\x1e\xfc\x81\x1d""Eh@N\xef";

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

    // reverse
    for (size_t i = 0; i < (sizeof goal - 1) / 2; i++)
        swap(payload, i, sizeof goal -2 - i);

    swap(payload, 1, 5);
    swap(payload, 2, 0x20);


    for (size_t i = 0; i < (sizeof goal - 1) / 2; i++)
        swap(payload, i, sizeof goal -2 - i);


    for (size_t i = 0; i < (sizeof goal -1); i++)
    {
       switch (i % 7)
       {
           case 0:
           {
               payload[(int64_t)i] ^= 0x79;
               break;
           }
           case 1:
           {
               payload[(int64_t)i] ^= 0x97;
               break;
           }
           case 2:
           {
               payload[(int64_t)i] ^= 0xe4;
               break;
           }
           case 3:
           {
               payload[(int64_t)i] ^= 0x25;
               break;
           }
           case 4:
           {
               payload[(int64_t)i] ^= 0x24;
               break;
           }
           case 5:
           {
               payload[(int64_t)i] ^= 0x1f;
               break;
           }
           case 6:
           {
               payload[(int64_t)i] ^= 0x4a;
               break;
           }
       }
    }

    swap(payload, 0x16, 0x23);

    for (size_t i = 0; i < (sizeof goal - 1) / 2; i++)
        swap(payload, i, sizeof goal -2 - i);



    write(STDOUT_FILENO, payload, sizeof goal-1);
}


