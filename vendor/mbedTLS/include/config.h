#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/*
 * Minimal mbedTLS configuration for TLS 1.2 client support.
 * Enable additional features or ciphersuites as needed.
 */

/* Platform/utility layers */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_TIMING_C
#define MBEDTLS_NET_C

/* Entropy/RNG */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* Crypto primitives */
#define MBEDTLS_AES_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD5_C
#define MBEDTLS_MD_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_C
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_GCM_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C

/* X.509 and public key parsing */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

/* TLS stack */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

#endif /* MBEDTLS_CONFIG_H */
