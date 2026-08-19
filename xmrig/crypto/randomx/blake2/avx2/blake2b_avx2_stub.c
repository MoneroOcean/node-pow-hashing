#include <stddef.h>

#include "../blake2.h"

int blake2b_avx2(void* out, size_t outlen, const void* in, size_t inlen)
{
    return rx_blake2b_default(out, outlen, in, inlen);
}
