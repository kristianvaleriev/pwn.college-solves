#include <stdio.h>

#define TRAINING_RETRIES 400
#define THRESHOLD_GIVE 0x30

void fn(void)
{
    size_t avg_hit = 0, avg_miss = 0;

    // flush_all(lines, count)
    
    // Dummy run
    for (int i = 0; i < TRAINING_RETRIES; i++) {
        // size_t time = measure(ptr)
    }

    // flush_all 

    // real_run
    for (int i = 0; i < TRAINING_RETRIES; i++) 
    {
        size_t time = 0; // = measure(ptr)
        avg_hit >>= 2;
        avg_hit += time;
    }

    threshold = avg_hit + THRESHOLD_GIVE;
}
