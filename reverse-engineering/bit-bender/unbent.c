#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char goal[] = "cwtRyFoKjwOzpzTR";

int main(void)
{
    unsigned char* result = malloc(sizeof goal);
    
    for (size_t i = 0; i < sizeof goal-1; i++)
    {
        result[i] = (goal[i] >> 2) | (goal[i] << 6);
        result[i] += 0x20;
        
        printf("0x%X %c\n", result[i], result[i]);
    }
    puts("\n");

    unsigned char ch;
    for (size_t i = 0; i < sizeof goal-1; i++)
    {
        ch = result[i];
        ch -= 0x20;
        ch = (ch << 2) | (ch >> 6);

        printf("0x%X %c\n", ch, ch);
    }

    puts("");
}
