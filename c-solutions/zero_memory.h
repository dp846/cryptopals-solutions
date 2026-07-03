#ifndef ZERO_MEMORY
#define ZERO_MEMORY 1

// Removed for CERT DCL37-C
// #define __STDC_WANT_LIB_EXT1__ 1

#include <stdlib.h>
#include <string.h>

void* zero_memory(void* pointer, size_t size_data, size_t size_to_remove) {
#ifdef __STDC_LIB_EXT1__
    memset_s(pointer, size_data, 0, size_to_remove);
#else
    if (size_to_remove > size_data)
        size_to_remove = size_data;
    volatile unsigned char* p = (volatile unsigned char*)pointer;

    while (size_to_remove--) {
        *p++ = 0;
    }
#endif
    return pointer;
}

#endif // ZERO_MEMORY
