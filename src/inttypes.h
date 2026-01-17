#ifndef INTTYPES_H_VC6_SHIM
#define INTTYPES_H_VC6_SHIM

#include <stddef.h>

/* VC6 doesn't define SIZE_MAX */
#ifndef SIZE_MAX
# ifdef _WIN64
#  define SIZE_MAX ((size_t)0xFFFFFFFFFFFFFFFFui64)
# else
#  define SIZE_MAX ((size_t)0xFFFFFFFFu)
# endif
#endif

/* minimal PRI macros if anything asks */
#ifndef PRIu64
# define PRIu64 "I64u"
#endif
#ifndef PRId64
# define PRId64 "I64d"
#endif

#endif
