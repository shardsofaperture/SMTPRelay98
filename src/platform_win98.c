#include <time.h>

/* mbedTLS calls this when MBEDTLS_PLATFORM_TIME_ALT is enabled */
struct tm *mbedtls_platform_gmtime_r( const time_t *tt, struct tm *tm_buf )
{
    struct tm *tmp = gmtime(tt);
    if( !tmp ) return 0;
    *tm_buf = *tmp;
    return tm_buf;
}
