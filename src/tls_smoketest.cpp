#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

extern "C" {
#include "../vendor/mbedTLS/include/mbedtls/ssl.h"
#include "../vendor/mbedTLS/include/mbedtls/entropy.h"
#include "../vendor/mbedTLS/include/mbedtls/ctr_drbg.h"
#include "../vendor/mbedTLS/include/mbedtls/error.h"
}

/* pull these from main.cpp */
extern "C" SOCKET connect_with_timeout(const char *host, int port, int timeoutMs);
extern "C" int bio_send_dbg(void *ctx, const unsigned char *buf, size_t len);
extern "C" int bio_recv_dbg(void *ctx, unsigned char *buf, size_t len);

static void write_err(FILE *f, int ret)
{
    char buf[256];
    mbedtls_strerror(ret, buf, sizeof(buf));
    fprintf(f, "mbedTLS error: -0x%04X (%d) %s\r\n", (unsigned int)(-ret), ret, buf);
}

extern "C" void tls_smoketest(void)
{
    FILE *f = fopen("tls_test.log", "wb");
    if(!f) return;

    const char *host = "example.com";
    int port = 443;

    fprintf(f, "TLS smoketest start\r\n");

    SOCKET s = connect_with_timeout(host, port, 10000);
    if(s == INVALID_SOCKET)
    {
        fprintf(f, "TCP connect failed\r\n");
        fclose(f);
        return;
    }
    SOCKET *psock = new SOCKET;
    *psock = s;

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);

    const char *pers = "tlswrap98";
    int ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                    (const unsigned char*)pers, (int)strlen(pers));
    if(ret != 0) { fprintf(f, "ctr_drbg_seed failed\r\n"); write_err(f, ret); goto done; }

    ret = mbedtls_ssl_config_defaults(&conf,
                                     MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if(ret != 0) { fprintf(f, "config_defaults failed\r\n"); write_err(f, ret); goto done; }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    /* Force TLS 1.2 only */
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if(ret != 0) { fprintf(f, "ssl_setup failed\r\n"); write_err(f, ret); goto done; }

    ret = mbedtls_ssl_set_hostname(&ssl, host); /* SNI */
    if(ret != 0) { fprintf(f, "set_hostname failed\r\n"); write_err(f, ret); goto done; }

    mbedtls_ssl_set_bio(&ssl, psock, bio_send_dbg, bio_recv_dbg, NULL);

    fprintf(f, "Handshake...\r\n");
    while((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        fprintf(f, "handshake failed\r\n");
        write_err(f, ret);
        goto done;
    }

    fprintf(f, "Handshake OK\r\n");
    fprintf(f, "Ciphersuite: %s\r\n", mbedtls_ssl_get_ciphersuite(&ssl));

    {
        const char *req =
            "GET / HTTP/1.0\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n"
            "\r\n";
        ret = mbedtls_ssl_write(&ssl, (const unsigned char*)req, (int)strlen(req));
        fprintf(f, "write ret=%d\r\n", ret);
    }

    {
        unsigned char buf[1024];
        int n, total = 0;
        while((n = mbedtls_ssl_read(&ssl, buf, sizeof(buf)-1)) > 0 && total < 4096)
        {
            buf[n] = 0;
            fwrite(buf, 1, n, f);
            total += n;
        }
        fprintf(f, "\r\nread done n=%d\r\n", n);
        if(n < 0 && n != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            write_err(f, n);
    }

done:
    fprintf(f, "\r\nTLS smoketest end\r\n");
    fclose(f);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);

    closesocket(*psock);
    delete psock;
}
