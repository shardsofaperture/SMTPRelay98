#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* =========================================================================
   mbedTLS 2.14.6 config for Win98 + MSVC6
   - TLS 1.2 client only
   - X.509 cert parsing + verification
   - ECDHE_RSA preferred (modern), RSA fallback
   - AES-128-GCM preferred, AES-CBC fallback
   - No MBEDTLS_DEBUG_C (VC6 can't handle variadic debug macros)

   ========================================================================= */

/* ---------------- Platform / portability ---------------- */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS 0
#define MBEDTLS_PLATFORM_UTIL_C

/*------------------Time Fix I guess --------------*/
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_GMTIME_R_ALT


/*------------------509 library fix ----------*/
#define MBEDTLS_X509_CHECK_KEY_USAGE
#define MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE



/* ---------------- Basic utilities ---------------- */
#define MBEDTLS_BASE64_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C

/* ---------------- Error strings (handy) ---------------- */
#define MBEDTLS_ERROR_C

/* ---------------- Bignum / Public Key ---------------- */
#define MBEDTLS_BIGNUM_C

#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

/* ---------------- X.509 ---------------- */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* Verification */
#define MBEDTLS_X509_CRT_PARSE_C

/* ---------------- RNG ---------------- */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_POLL_C
#define MBEDTLS_CTR_DRBG_C

/* ---------------- Hash / MAC ---------------- */
#define MBEDTLS_MD_C
#define MBEDTLS_MD_WRAP_C

#define MBEDTLS_SHA256_C
/* SHA-1 often still needed for legacy/intermediate cert chains */
#define MBEDTLS_SHA1_C

/* Optional: some chains still use MD5 signatures historically.
   You can try disabling later if you want. */
#define MBEDTLS_MD5_C

/* HMAC is used by TLS and some PRFs */
#define MBEDTLS_CMAC_C

/* ---------------- Ciphers ---------------- */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_WRAP_C

#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C

/* CBC fallback */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_PADDING_PKCS7

/* Optional: CTR used in some code paths */
#define MBEDTLS_CIPHER_MODE_CTR

/* ---------------- RSA + ECC for modern TLS ---------------- */
#define MBEDTLS_RSA_C

#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_CURVES_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C

/* Curves */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
/* If you want *maximum* compatibility, you can also enable secp521r1,
   but it costs more CPU. */
/* #define MBEDTLS_ECP_DP_SECP521R1_ENABLED */

#define MBEDTLS_ECP_NIST_OPTIM

/* ---------------- TLS (client) ---------------- */
#define MBEDTLS_SSL_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_CIPHERSUITES_C
#define MBEDTLS_SSL_PROTO_TLS1_2

/* Key exchanges */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
/* Some servers use ECDSA certs; enable if you need it */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
/* RSA key exchange fallback (older servers) */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

/* ---------------- Disable debug module for VC6 ---------------- */
/* #define MBEDTLS_DEBUG_C */

/* ---------------- Hard-disable PSA crypto (avoid extra modules) ---------------- */
#undef MBEDTLS_PSA_CRYPTO_C

/* ---------------- Sanity-check config ---------------- */
#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
