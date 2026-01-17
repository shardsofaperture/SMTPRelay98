/* src\mbedtls_platform_shims.c */
#include <stddef.h>
#include <stdlib.h>

/* mbedTLS expects this exact name */
void mbedtls_platform_zeroize( void *buf, size_t len )
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while( len-- ) *p++ = 0;
}

/* Pentium III supports RDTSC; VC6 inline asm is fine */
unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long lo;
    __asm {
        rdtsc
        mov lo, eax
    }
    return lo;
}

/* Bulletproof allocator hooks (avoids “platform.c not pulled” issues) */
void *mbedtls_calloc( size_t n, size_t size ) { return calloc( n, size ); }
void  mbedtls_free( void *p ) { free( p ); }
