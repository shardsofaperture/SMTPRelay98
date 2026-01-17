#ifndef STDINT_H_VC6
#define STDINT_H_VC6

/* MSVC 6.0 / Win9x compatibility stdint.h */

typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef signed short       int16_t;
typedef unsigned short     uint16_t;
typedef signed int         int32_t;
typedef unsigned int       uint32_t;

typedef signed __int64     int64_t;
typedef unsigned __int64   uint64_t;

typedef int                intptr_t;
typedef unsigned int       uintptr_t;

#define INT8_MIN   (-128)
#define INT8_MAX   (127)
#define UINT8_MAX  (255U)

#define INT16_MIN  (-32768)
#define INT16_MAX  (32767)
#define UINT16_MAX (65535U)

#define INT32_MIN  (-2147483647 - 1)
#define INT32_MAX  (2147483647)
#define UINT32_MAX (4294967295U)

#define INT64_MIN  (-9223372036854775807i64 - 1i64)
#define INT64_MAX  (9223372036854775807i64)
#define UINT64_MAX (18446744073709551615ui64)

#endif
