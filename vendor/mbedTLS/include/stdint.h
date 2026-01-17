/* vendor\mbedTLS\include\stdint.h  (VC6 / Win98 shim) */
#ifndef _STDINT_H_
#define _STDINT_H_

typedef signed char         int8_t;
typedef unsigned char       uint8_t;

typedef signed short        int16_t;
typedef unsigned short      uint16_t;

typedef signed long         int32_t;
typedef unsigned long       uint32_t;

typedef signed __int64      int64_t;
typedef unsigned __int64    uint64_t;

typedef unsigned int        uintptr_t;
typedef signed int          intptr_t;

/* limits (only what most libs use) */
#define INT8_MIN   (-128)
#define INT8_MAX   (127)
#define UINT8_MAX  (255)

#define INT16_MIN  (-32768)
#define INT16_MAX  (32767)
#define UINT16_MAX (65535)

#define INT32_MIN  (-2147483647L - 1)
#define INT32_MAX  (2147483647L)
#define UINT32_MAX (4294967295UL)

#endif /* _STDINT_H_ */
