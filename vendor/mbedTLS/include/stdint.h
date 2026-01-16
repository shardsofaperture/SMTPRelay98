#ifndef MBEDTLS_COMPAT_STDINT_H
#define MBEDTLS_COMPAT_STDINT_H

/*
 * Minimal stdint.h compatibility header for older MSVC versions (e.g., VC6).
 * This is included via <stdint.h> from the mbedTLS headers when building
 * with compilers that do not provide the standard header.
 */

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef signed __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef signed __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef signed __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef signed __int64 int64_t;
typedef unsigned __int64 uint64_t;

typedef signed __int32 intptr_t;
typedef unsigned __int32 uintptr_t;
#else
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed long long int64_t;
typedef unsigned long long uint64_t;

typedef signed long intptr_t;
typedef unsigned long uintptr_t;
#endif

#endif /* MBEDTLS_COMPAT_STDINT_H */
