#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* =========================================================================
   Minimal-ish mbedTLS config for Win98 + VC6, TLS 1.2 client
   - No PSA crypto
   - X.509 cert parsing enabled (even if you set VerifyCert=0)
   - ECDHE + RSA enabled for modern servers
   ========================================================================= */

/* ---- Platform / portability ---- */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS 0
#define MBEDTLS_PLATFORM_UTIL_C

/* ---- Basic utilities ---- */
#define MBEDTLS_BASE64_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C

/* ---- Bignum / PK / X509 ---- */
#define MBEDTLS_BIGNUM_C

#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* ---- RNG ---- */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_POLL_C
#define MBEDTLS_CTR_DRBG_C

/* ---- Hash / MAC / generic MD ---- */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_MD5_C  /* keep for compatibility; can try removing later */

/* ---- Ciphers ---- */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C

/* Optional modes/helpers commonly pulled in by cipher glue */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_PADDING_PKCS7

/* ---- RSA + ECC for modern TLS ---- */
#define MBEDTLS_RSA_C

#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_CURVE25519_ENABLED 0 /* keep off unless you need it */
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C

/* Enable a couple of widely-used curves */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM

/* ---- TLS ---- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_CIPHERSUITES_C
#define MBEDTLS_SSL_PROTO_TLS1_2

/* Key exchanges commonly required by modern servers */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

/* ---- Helpful for debugging ---- */
#define MBEDTLS_ERROR_C
/* #define MBEDTLS_DEBUG_C */  /* enable if you want mbedtls debug output */

/* ---- Hard-disable PSA crypto (avoid extra sources + headaches) ---- */
#undef MBEDTLS_PSA_CRYPTO_C

/* ---- Sanity check config ---- */
#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
