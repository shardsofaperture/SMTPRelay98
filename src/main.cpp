#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include <string.h>



#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#endif

#if defined(_MSC_VER) && (_MSC_VER <= 1200)


static int vc6_snprintf(char* dst, size_t dstSize, const char* fmt, ...)
{
    if (!dst || dstSize == 0) return -1;
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf(dst, dstSize, fmt, ap);
    va_end(ap);
    dst[dstSize - 1] = '\0';
    return n;
}
#define snprintf vc6_snprintf
#endif

#include "../vendor/mbedTLS/include/mbedtls/ssl.h"
#include "../vendor/mbedTLS/include/mbedtls/ctr_drbg.h"
#include "../vendor/mbedTLS/include/mbedtls/entropy.h"
#include "../vendor/mbedTLS/include/mbedtls/error.h"
#include "../vendor/mbedTLS/include/mbedtls/x509_crt.h"
#include "../vendor/mbedTLS/include/mbedtls/net_sockets.h"

#define APP_CLASS_NAME "TLSWrap98Window"
#define APP_TRAY_TOOLTIP "TLSWrap98"
#define APP_INI_NAME "tlswrap98.ini"
#define APP_LOG_NAME "tlswrap98.log"

#define WM_TRAYICON (WM_USER + 100)
#define ID_TRAY_STARTSTOP 1001
#define ID_TRAY_OPENCFG 1002
#define ID_TRAY_VIEWLOG 1003
#define ID_TRAY_EXIT 1004

#define LOG_ERROR 0
#define LOG_INFO 1
#define LOG_DEBUG 2

#define MAX_TUNNELS 32

enum TunnelMode
{
    MODE_DIRECT_TLS = 0,
    MODE_STARTTLS_SMTP = 1
};

struct GlobalConfig
{
    char logFile[MAX_PATH];
    int logLevel;
    int connectTimeoutMs;
    int ioTimeoutMs;
    int startTlsTimeoutMs;
};

struct TunnelConfig
{
    char name[64];
    char listenAddr[64];
    int listenPort;
    char announceName[256];
    char remoteHost[256];
    int remotePort;
    TunnelMode mode;
    int verifyCert;
    char sni[256];
    int logLevel;
};

struct TunnelState
{
    TunnelConfig cfg;
    SOCKET listenSock;
    HANDLE thread;
    volatile LONG running;
};

struct ConnectionContext
{
    TunnelConfig cfg;
    SOCKET clientSock;
    SOCKET remoteSock;
};

static GlobalConfig g_config;
static std::vector<TunnelState *> g_tunnels;
static HINSTANCE g_hInstance = NULL;
static HWND g_hWnd = NULL;
static volatile LONG g_running = 0;
static volatile LONG g_shutdown = 0;
static CRITICAL_SECTION g_logLock;

static void log_message(int level, const char *fmt, ...)
{
    if (level > g_config.logLevel)
    {
        return;
    }

    EnterCriticalSection(&g_logLock);
    FILE *fp = fopen(g_config.logFile, "a+");
    if (fp)
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        va_list args;
        va_start(args, fmt);
        vfprintf(fp, fmt, args);
        va_end(args);

        fprintf(fp, "\r\n");
        fclose(fp);
    }
    LeaveCriticalSection(&g_logLock);
}

static void log_line(const char *tag, const char *fmt, ...)
{
    EnterCriticalSection(&g_logLock);
    FILE *fp = fopen(APP_LOG_NAME, "a+");
    if (fp)
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d %s ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, tag);

        va_list args;
        va_start(args, fmt);
        vfprintf(fp, fmt, args);
        va_end(args);

        fprintf(fp, "\r\n");
        fclose(fp);
    }
    LeaveCriticalSection(&g_logLock);
}

static void get_app_path(char *buffer, size_t size)
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *slash = strrchr(path, '\\');
    if (slash)
    {
        *(slash + 1) = '\0';
    }
    strncpy(buffer, path, (int)size - 1);
    buffer[size - 1] = '\0';
}

static void build_path(char *outPath, size_t size, const char *fileName)
{
    char base[MAX_PATH];
    get_app_path(base, sizeof(base));
    snprintf(outPath, size, "%s%s", base, fileName);
}

static void load_default_config()
{
    memset(&g_config, 0, sizeof(g_config));
    build_path(g_config.logFile, sizeof(g_config.logFile), APP_LOG_NAME);
    g_config.logLevel = LOG_INFO;
    g_config.connectTimeoutMs = 10000;
    g_config.ioTimeoutMs = 300000;
    g_config.startTlsTimeoutMs = 10000;
}

static TunnelMode parse_mode(const char *mode)
{
    if (mode && lstrcmpiA(mode, "STARTTLS_SMTP") == 0)
    {
        return MODE_STARTTLS_SMTP;
    }
    return MODE_DIRECT_TLS;
}

static void load_global_config(const char *iniPath)
{
    GetPrivateProfileStringA("global", "LogFile", g_config.logFile,
                            g_config.logFile, MAX_PATH, iniPath);
    g_config.logLevel = GetPrivateProfileIntA("global", "LogLevel",
                                              g_config.logLevel, iniPath);
    g_config.connectTimeoutMs = GetPrivateProfileIntA("global", "ConnectTimeoutMs",
                                                      g_config.connectTimeoutMs, iniPath);
    g_config.ioTimeoutMs = GetPrivateProfileIntA("global", "IoTimeoutMs",
                                                 g_config.ioTimeoutMs, iniPath);
    g_config.startTlsTimeoutMs = GetPrivateProfileIntA("global", "StartTlsTimeoutMs",
                                                       g_config.startTlsTimeoutMs, iniPath);
}

static void load_tunnel_config(const char *iniPath, const char *section, TunnelConfig *cfg)
{
    memset(cfg, 0, sizeof(TunnelConfig));
    strncpy(cfg->name, section, sizeof(cfg->name) - 1);
    GetPrivateProfileStringA(section, "ListenAddr", "127.0.0.1",
                             cfg->listenAddr, sizeof(cfg->listenAddr), iniPath);
    cfg->listenPort = GetPrivateProfileIntA(section, "ListenPort", 0, iniPath);
    GetPrivateProfileStringA(section, "AnnounceName", "",
                             cfg->announceName, sizeof(cfg->announceName), iniPath);
    GetPrivateProfileStringA(section, "RemoteHost", "",
                             cfg->remoteHost, sizeof(cfg->remoteHost), iniPath);
    cfg->remotePort = GetPrivateProfileIntA(section, "RemotePort", 0, iniPath);
    cfg->verifyCert = GetPrivateProfileIntA(section, "VerifyCert", 0, iniPath);
    GetPrivateProfileStringA(section, "SNI", "",
                             cfg->sni, sizeof(cfg->sni), iniPath);

    char modeBuf[64];
    GetPrivateProfileStringA(section, "Mode", "DIRECT_TLS", modeBuf, sizeof(modeBuf), iniPath);
    cfg->mode = parse_mode(modeBuf);

    cfg->logLevel = GetPrivateProfileIntA(section, "LogLevel", g_config.logLevel, iniPath);
}

static void free_tunnels()
{
    for (size_t i = 0; i < g_tunnels.size(); ++i)
    {
        delete g_tunnels[i];
    }
    g_tunnels.clear();
}

static bool load_config()
{
    char iniPath[MAX_PATH];
    build_path(iniPath, sizeof(iniPath), APP_INI_NAME);

    load_default_config();
    load_global_config(iniPath);

    char sectionNames[4096];
    DWORD len = GetPrivateProfileSectionNamesA(sectionNames, sizeof(sectionNames), iniPath);
    if (len == 0)
    {
        log_message(LOG_ERROR, "No INI sections found in %s", iniPath);
        return false;
    }

    free_tunnels();

    const char *ptr = sectionNames;
    while (*ptr)
    {
        if (_strnicmp(ptr, "tunnel ", 7) == 0)
        {
            TunnelConfig cfg;
            load_tunnel_config(iniPath, ptr, &cfg);
            if (cfg.listenPort > 0 && cfg.remotePort > 0 && cfg.remoteHost[0] != '\0')
            {
                TunnelState *state = new TunnelState();
                memset(state, 0, sizeof(TunnelState));
                state->cfg = cfg;
                state->listenSock = INVALID_SOCKET;
                state->thread = NULL;
                state->running = 0;
                g_tunnels.push_back(state);
            }
        }
        ptr += strlen(ptr) + 1;
    }

    if (g_tunnels.empty())
    {
        log_message(LOG_ERROR, "No valid tunnel definitions found in %s", iniPath);
        return false;
    }

    return true;
}

static int socket_set_blocking(SOCKET s, bool blocking)
{
    u_long mode = blocking ? 0 : 1;
    return ioctlsocket(s, FIONBIO, &mode);
}

extern "C" SOCKET connect_with_timeout(const char *host, int port, int timeoutMs)
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        return INVALID_SOCKET;
    }

    struct hostent *he = gethostbyname(host);
    if (!he)
    {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    socket_set_blocking(sock, false);
    int ret = connect(sock, (sockaddr *)&addr, sizeof(addr));
    if (ret == SOCKET_ERROR)
    {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS)
        {
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    ret = select(0, NULL, &writeSet, NULL, &tv);
    if (ret <= 0 || !FD_ISSET(sock, &writeSet))
    {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    socket_set_blocking(sock, true);
    return sock;
}

static int recv_line(SOCKET sock, char *buffer, int size, int timeoutMs)
{
    int total = 0;
    while (total < size - 1)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(sock, &readSet);
        timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        int ret = select(0, &readSet, NULL, NULL, &tv);
        if (ret <= 0)
        {
            return -1;
        }
        char c;
        ret = recv(sock, &c, 1, 0);
        if (ret <= 0)
        {
            return -1;
        }
        buffer[total++] = c;
        if (c == '\n')
        {
            break;
        }
    }
    buffer[total] = '\0';
    return total;
}

static bool send_all_plain(SOCKET sock, const char *buffer, int length)
{
    int sent = 0;
    while (sent < length)
    {
        int ret = send(sock, buffer + sent, length - sent, 0);
        if (ret <= 0)
        {
            return false;
        }
        sent += ret;
    }
    return true;
}

static bool smtp_discard_banner(SOCKET sock, int timeoutMs)
{
    char line[512];
    for (;;)
    {
        int len = recv_line(sock, line, sizeof(line), timeoutMs);
        if (len <= 0)
        {
            return false;
        }
        if (len >= 4 && line[3] == '-')
        {
            continue;
        }
        break;
    }
    return true;
}

static bool smtp_forward_response(SOCKET remoteSock, SOCKET clientSock, int timeoutMs, bool *gotOk)
{
    char line[512];
    bool ok = false;
    for (;;)
    {
        int len = recv_line(remoteSock, line, sizeof(line), timeoutMs);
        if (len <= 0)
        {
            return false;
        }
        if (!send_all_plain(clientSock, line, len))
        {
            return false;
        }
        if (len >= 4 && line[3] == '-')
        {
            continue;
        }
        if (strncmp(line, "250", 3) == 0)
        {
            ok = true;
        }
        break;
    }
    if (gotOk)
    {
        *gotOk = ok;
    }
    return true;
}

static bool smtp_starttls(SOCKET sock, int timeoutMs, int logLevel)
{
    char line[512];
    if (recv_line(sock, line, sizeof(line), timeoutMs) <= 0)
    {
        log_message(logLevel, "SMTP: failed to read banner");
        return false;
    }

    const char *ehlo = "EHLO tlswrap98\r\n";
    send(sock, ehlo, (int)strlen(ehlo), 0);

    bool gotOk = false;
    for (;;)
    {
        if (recv_line(sock, line, sizeof(line), timeoutMs) <= 0)
        {
            break;
        }
        if (strncmp(line, "250 ", 4) == 0)
        {
            gotOk = true;
            break;
        }
    }

    if (!gotOk)
    {
        log_message(logLevel, "SMTP: EHLO not accepted");
        return false;
    }

    const char *starttls = "STARTTLS\r\n";
    send(sock, starttls, (int)strlen(starttls), 0);

    if (recv_line(sock, line, sizeof(line), timeoutMs) <= 0)
    {
        log_message(logLevel, "SMTP: STARTTLS no response");
        return false;
    }
    if (strncmp(line, "220", 3) != 0)
    {
        log_message(logLevel, "SMTP: STARTTLS rejected: %s", line);
        return false;
    }
    return true;
}

extern "C" int bio_send_dbg(void *ctx, const unsigned char *buf, size_t len)
{
    SOCKET sock = *((SOCKET *)ctx);
    int ret = send(sock, (const char *)buf, (int)len, 0);
    if (ret == SOCKET_ERROR)
    {
        int wsaErr = WSAGetLastError();
        log_line("[TLS->R]", "send FAILED sock=%ld len=%u WSA=%d",
                 (long)sock, (unsigned)len, wsaErr);
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

extern "C" int bio_recv_dbg(void *ctx, unsigned char *buf, size_t len)
{
    SOCKET sock = *((SOCKET *)ctx);
    int ret = recv(sock, (char *)buf, (int)len, 0);
    if (ret == 0)
    {
        log_line("[TLS<-R]", "remote closed (recv=0)");
    }
    if (ret == SOCKET_ERROR)
    {
        int wsaErr = WSAGetLastError();
        log_line("[TLS<-R]", "TLS recv failed: wsa=%d", wsaErr);
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;
}

static bool tls_handshake(SOCKET *psock, TunnelConfig *cfg, mbedtls_ssl_context *ssl,
                          mbedtls_ssl_config *conf, mbedtls_ctr_drbg_context *ctr_drbg,
                          mbedtls_entropy_context *entropy, mbedtls_x509_crt *cacert)
{
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);
    mbedtls_x509_crt_init(cacert);

    const char *pers = "tlswrap98";
    int ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        log_message(cfg->logLevel, "TLS: RNG seed failed: %d", ret);
        return false;
    }

    ret = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        log_message(cfg->logLevel, "TLS: config defaults failed: %d", ret);
        return false;
    }

    if (cfg->verifyCert)
    {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    else
    {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    ret = mbedtls_ssl_setup(ssl, conf);
    if (ret != 0)
    {
        log_message(cfg->logLevel, "TLS: ssl_setup failed: %d", ret);
        return false;
    }

    if (cfg->sni[0] != '\0')
    {
        mbedtls_ssl_set_hostname(ssl, cfg->sni);
    }
    else
    {
        mbedtls_ssl_set_hostname(ssl, cfg->remoteHost);
    }

    mbedtls_ssl_set_bio(ssl, psock, bio_send_dbg, bio_recv_dbg, NULL);

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
    {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }
        log_message(cfg->logLevel, "TLS: handshake failed: -0x%04x", -ret);
        return false;
    }

    return true;
}

static void tls_cleanup(mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf,
                        mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy,
                        mbedtls_x509_crt *cacert)
{
    mbedtls_ssl_close_notify(ssl);
    mbedtls_ssl_free(ssl);
    mbedtls_ssl_config_free(conf);
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    mbedtls_x509_crt_free(cacert);
}

static bool smtp_lazy_starttls(SOCKET clientSock, SOCKET *remoteSockOut, TunnelConfig *cfg,
                               mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf,
                               mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy,
                               mbedtls_x509_crt *cacert)
{
    char line[512];
    int len = recv_line(clientSock, line, sizeof(line), g_config.ioTimeoutMs);
    if (len <= 0)
    {
        log_line("[SMTP]", "local client closed before command");
        return false;
    }

    SOCKET rs = connect_with_timeout(cfg->remoteHost, cfg->remotePort,
                                     g_config.connectTimeoutMs);
    if (rs == INVALID_SOCKET)
    {
        log_message(cfg->logLevel, "%s: connect failed", cfg->name);
        return false;
    }
    *remoteSockOut = rs;

    if (!smtp_discard_banner(*remoteSockOut, g_config.startTlsTimeoutMs))
    {
        log_message(cfg->logLevel, "[SMTP] failed to read remote banner");
        closesocket(*remoteSockOut);
        *remoteSockOut = INVALID_SOCKET;
        return false;
    }
    log_message(cfg->logLevel, "[SMTP] connected upstream, discarded remote 220 banner");

    bool upgraded = false;
    bool haveLine = true;
    while (!upgraded)
    {
        if (!haveLine)
        {
            len = recv_line(clientSock, line, sizeof(line), g_config.ioTimeoutMs);
            if (len <= 0)
            {
                closesocket(*remoteSockOut);
                *remoteSockOut = INVALID_SOCKET;
                return false;
            }
        }
        haveLine = false;

        bool isEhlo = (_strnicmp(line, "EHLO", 4) == 0) || (_strnicmp(line, "HELO", 4) == 0);
        if (!send_all_plain(*remoteSockOut, line, len))
        {
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }

        bool gotOk = false;
        if (!smtp_forward_response(*remoteSockOut, clientSock, g_config.startTlsTimeoutMs, &gotOk))
        {
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }

        if (isEhlo && gotOk)
        {
            log_message(cfg->logLevel, "[SMTP] relayed EHLO, now upgrading upstream via STARTTLS");
            if (!send_all_plain(*remoteSockOut, "STARTTLS\r\n", 10))
            {
                closesocket(*remoteSockOut);
                *remoteSockOut = INVALID_SOCKET;
                return false;
            }
            len = recv_line(*remoteSockOut, line, sizeof(line), g_config.startTlsTimeoutMs);
            if (len <= 0 || strncmp(line, "220", 3) != 0)
            {
                log_message(cfg->logLevel, "[SMTP] STARTTLS rejected: %s", line);
                closesocket(*remoteSockOut);
                *remoteSockOut = INVALID_SOCKET;
                return false;
            }
            if (!tls_handshake(remoteSockOut, cfg, ssl, conf, ctr_drbg, entropy, cacert))
            {
                closesocket(*remoteSockOut);
                *remoteSockOut = INVALID_SOCKET;
                return false;
            }
            log_message(cfg->logLevel, "[SMTP] upstream TLS handshake OK");
            upgraded = true;
        }
    }

    return true;
}

static DWORD WINAPI connection_thread(LPVOID param)
{
    ConnectionContext *ctx = (ConnectionContext *)param;
    TunnelConfig cfg = ctx->cfg;
    SOCKET clientSock = ctx->clientSock;
    SOCKET remoteSock = ctx->remoteSock;
    delete ctx;

    if (cfg.mode == MODE_STARTTLS_SMTP)
    {
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;
        mbedtls_x509_crt cacert;

        if (!smtp_lazy_starttls(clientSock, &remoteSock, &cfg, &ssl, &conf,
                                &ctr_drbg, &entropy, &cacert))
        {
            closesocket(clientSock);
            return 0;
        }

        log_message(cfg.logLevel, "%s: STARTTLS completed", cfg.name);

        DWORD lastActivity = GetTickCount();
        char buffer[4096];

        while (!g_shutdown)
        {
            DWORD now = GetTickCount();
            if ((int)(now - lastActivity) > g_config.ioTimeoutMs)
            {
                log_message(cfg.logLevel, "%s: idle timeout", cfg.name);
                break;
            }

            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(clientSock, &readSet);
            FD_SET(remoteSock, &readSet);
            timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int ret = select(0, &readSet, NULL, NULL, &tv);
            if (ret == SOCKET_ERROR)
            {
                break;
            }
            if (ret == 0)
            {
                continue;
            }

            if (FD_ISSET(clientSock, &readSet))
            {
                int r = recv(clientSock, buffer, sizeof(buffer), 0);
                if (r == 0)
                {
                    log_line("[L->APP]", "local client closed (recv=0)");
                    break;
                }
                if (r < 0)
                {
                    int wsaErr = WSAGetLastError();
                    log_line("[L->APP]", "local recv failed: wsa=%d", wsaErr);
                    break;
                }
                int sent = 0;
                while (sent < r)
                {
                    int w = mbedtls_ssl_write(&ssl, (const unsigned char *)buffer + sent, r - sent);
                    if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
                    {
                        continue;
                    }
                    if (w <= 0)
                    {
                        char errbuf[256];
                        mbedtls_strerror(w, errbuf, sizeof(errbuf));
                        log_line("[TLS->R]", "TLS write to remote failed: ret=%d (-0x%04x) %s",
                                 w, (unsigned int)(-w), errbuf);
                        goto smtp_cleanup;
                    }
                    sent += w;
                }
                lastActivity = GetTickCount();
            }

            if (FD_ISSET(remoteSock, &readSet))
            {
                int r = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, sizeof(buffer));
                if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
                {
                    continue;
                }
                if (r == 0)
                {
                    log_line("[TLS<-R]", "TLS close_notify received");
                    break;
                }
                if (r <= 0)
                {
                    char errbuf[256];
                    mbedtls_strerror(r, errbuf, sizeof(errbuf));
                    log_line("[TLS<-R]", "TLS read from remote failed: ret=%d (-0x%04x) %s",
                             r, (unsigned int)(-r), errbuf);
                    break;
                }
                int sent = 0;
                while (sent < r)
                {
                    int w = send(clientSock, buffer + sent, r - sent, 0);
                    if (w <= 0)
                    {
                        int wsaErr = WSAGetLastError();
                        log_line("[APP->L]", "send to local client failed: wsa=%d", wsaErr);
                        goto smtp_cleanup;
                    }
                    sent += w;
                }
                lastActivity = GetTickCount();
            }
        }

smtp_cleanup:
        tls_cleanup(&ssl, &conf, &ctr_drbg, &entropy, &cacert);
        closesocket(clientSock);
        closesocket(remoteSock);
        return 0;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;

    if (!tls_handshake(&remoteSock, &cfg, &ssl, &conf, &ctr_drbg, &entropy, &cacert))
    {
        closesocket(clientSock);
        closesocket(remoteSock);
        return 0;
    }

    log_message(cfg.logLevel, "%s: TLS handshake OK", cfg.name);

    DWORD lastActivity = GetTickCount();
    char buffer[4096];

    while (!g_shutdown)
    {
        DWORD now = GetTickCount();
        if ((int)(now - lastActivity) > g_config.ioTimeoutMs)
        {
            log_message(cfg.logLevel, "%s: idle timeout", cfg.name);
            break;
        }

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientSock, &readSet);
        FD_SET(remoteSock, &readSet);
        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(0, &readSet, NULL, NULL, &tv);
        if (ret == SOCKET_ERROR)
        {
            break;
        }
        if (ret == 0)
        {
            continue;
        }

        if (FD_ISSET(clientSock, &readSet))
        {
            int r = recv(clientSock, buffer, sizeof(buffer), 0);
            if (r == 0)
            {
                log_line("[L->APP]", "local client closed (recv=0)");
                break;
            }
            if (r < 0)
            {
                int wsaErr = WSAGetLastError();
                log_line("[L->APP]", "local recv failed: wsa=%d", wsaErr);
                break;
            }
            int sent = 0;
            while (sent < r)
            {
                int w = mbedtls_ssl_write(&ssl, (const unsigned char *)buffer + sent, r - sent);
                if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
                {
                    continue;
                }
                if (w <= 0)
                {
                    char errbuf[256];
                    mbedtls_strerror(w, errbuf, sizeof(errbuf));
                    log_line("[TLS->R]", "TLS write to remote failed: ret=%d (-0x%04x) %s",
                             w, (unsigned int)(-w), errbuf);
                    goto cleanup;
                }
                sent += w;
            }
            lastActivity = GetTickCount();
        }

        if (FD_ISSET(remoteSock, &readSet))
        {
            int r = mbedtls_ssl_read(&ssl, (unsigned char *)buffer, sizeof(buffer));
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                continue;
            }
            if (r == 0)
            {
                log_line("[TLS<-R]", "TLS close_notify received");
                break;
            }
            if (r <= 0)
            {
                char errbuf[256];
                mbedtls_strerror(r, errbuf, sizeof(errbuf));
                log_line("[TLS<-R]", "TLS read from remote failed: ret=%d (-0x%04x) %s",
                         r, (unsigned int)(-r), errbuf);
                break;
            }
            int sent = 0;
            while (sent < r)
            {
                int w = send(clientSock, buffer + sent, r - sent, 0);
                if (w <= 0)
                {
                    int wsaErr = WSAGetLastError();
                    log_line("[APP->L]", "send to local client failed: wsa=%d", wsaErr);
                    goto cleanup;
                }
                sent += w;
            }
            lastActivity = GetTickCount();
        }
    }

cleanup:
    tls_cleanup(&ssl, &conf, &ctr_drbg, &entropy, &cacert);
    closesocket(clientSock);
    closesocket(remoteSock);
    return 0;
}

static DWORD WINAPI listener_thread(LPVOID param)
{
    TunnelState *state = (TunnelState *)param;

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET)
    {
        log_message(LOG_ERROR, "%s: listen socket failed", state->cfg.name);
        return 0;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)state->cfg.listenPort);
    addr.sin_addr.s_addr = inet_addr(state->cfg.listenAddr);

    if (bind(listenSock, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        log_message(LOG_ERROR, "%s: bind failed", state->cfg.name);
        closesocket(listenSock);
        return 0;
    }

    if (listen(listenSock, 5) == SOCKET_ERROR)
    {
        log_message(LOG_ERROR, "%s: listen failed", state->cfg.name);
        closesocket(listenSock);
        return 0;
    }

    state->listenSock = listenSock;
    state->running = 1;
    log_message(LOG_INFO, "%s: listening on %s:%d", state->cfg.name,
                state->cfg.listenAddr, state->cfg.listenPort);

    while (state->running && !g_shutdown)
    {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET)
        {
            if (g_shutdown)
            {
                break;
            }
            continue;
        }

        SOCKET remoteSock = INVALID_SOCKET;
        if (state->cfg.mode == MODE_STARTTLS_SMTP)
        {
            const char *announce = state->cfg.announceName[0] != '\0'
                                       ? state->cfg.announceName
                                       : "localhost";
            char banner[320];
            snprintf(banner, sizeof(banner), "220 %s ESMTP TLSWrap98\r\n", announce);
            if (!send_all_plain(clientSock, banner, (int)strlen(banner)))
            {
                closesocket(clientSock);
                continue;
            }
            log_message(state->cfg.logLevel, "[SMTP] sent local 220 banner");
        }
        else
        {
            remoteSock = connect_with_timeout(state->cfg.remoteHost,
                                              state->cfg.remotePort,
                                              g_config.connectTimeoutMs);
            if (remoteSock == INVALID_SOCKET)
            {
                log_message(state->cfg.logLevel, "%s: connect failed", state->cfg.name);
                closesocket(clientSock);
                continue;
            }
        }

        ConnectionContext *ctx = new ConnectionContext();
        ctx->cfg = state->cfg;
        ctx->clientSock = clientSock;
        ctx->remoteSock = remoteSock;

        DWORD threadId = 0;
        HANDLE hThread = CreateThread(NULL, 0, connection_thread, ctx, 0, &threadId);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            closesocket(clientSock);
            closesocket(remoteSock);
            delete ctx;
        }
    }

    closesocket(listenSock);
    state->listenSock = INVALID_SOCKET;
    return 0;
}

static void start_tunnels()
{
    if (g_running)
    {
        return;
    }

    if (!load_config())
    {
        MessageBoxA(g_hWnd, "No valid tunnels found. Check tlswrap98.ini.",
                    "TLSWrap98", MB_OK | MB_ICONERROR);
        return;
    }

    g_shutdown = 0;

    for (size_t i = 0; i < g_tunnels.size(); ++i)
    {
        TunnelState *state = g_tunnels[i];
        DWORD threadId = 0;
        state->thread = CreateThread(NULL, 0, listener_thread, state, 0, &threadId);
    }

    g_running = 1;
}

static void stop_tunnels()
{
    if (!g_running)
    {
        return;
    }

    g_shutdown = 1;

    size_t i;
    for (i = 0; i < g_tunnels.size(); ++i)
    {
        TunnelState *state = g_tunnels[i];
        state->running = 0;
        if (state->listenSock != INVALID_SOCKET)
        {
            closesocket(state->listenSock);
            state->listenSock = INVALID_SOCKET;
        }
    }

    for (i = 0; i < g_tunnels.size(); ++i)
    {
        TunnelState *state = g_tunnels[i];
        if (state->thread)
        {
            WaitForSingleObject(state->thread, 2000);
            CloseHandle(state->thread);
            state->thread = NULL;
        }
    }

    g_running = 0;
}

static void open_config()
{
    char iniPath[MAX_PATH];
    build_path(iniPath, sizeof(iniPath), APP_INI_NAME);
    ShellExecuteA(NULL, "open", iniPath, NULL, NULL, SW_SHOWNORMAL);
}

static void open_log()
{
    ShellExecuteA(NULL, "open", g_config.logFile, NULL, NULL, SW_SHOWNORMAL);
}

static void tray_add_icon()
{
    NOTIFYICONDATAA nid;
    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hWnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    lstrcpynA(nid.szTip, APP_TRAY_TOOLTIP, sizeof(nid.szTip));
    Shell_NotifyIconA(NIM_ADD, &nid);
}

static void tray_remove_icon()
{
    NOTIFYICONDATAA nid;
    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hWnd;
    nid.uID = 1;
    Shell_NotifyIconA(NIM_DELETE, &nid);
}

static void tray_show_menu()
{
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu)
    {
        return;
    }

    AppendMenuA(hMenu, MF_STRING, ID_TRAY_STARTSTOP, g_running ? "Stop" : "Start");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_OPENCFG, "Open Config");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_VIEWLOG, "View Log");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit");

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g_hWnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, g_hWnd, NULL);
    DestroyMenu(hMenu);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP)
        {
            tray_show_menu();
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_TRAY_STARTSTOP:
            if (g_running)
            {
                stop_tunnels();
            }
            else
            {
                start_tunnels();
            }
            return 0;
        case ID_TRAY_OPENCFG:
            open_config();
            return 0;
        case ID_TRAY_VIEWLOG:
            open_log();
            return 0;
        case ID_TRAY_EXIT:
            PostQuitMessage(0);
            return 0;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

extern "C" void tls_smoketest(void);


int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
g_hInstance = hInstance;

InitializeCriticalSection(&g_logLock);
load_default_config();

WSADATA wsaData;
if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
{
    MessageBoxA(NULL, "WSAStartup failed", "TLSWrap98", MB_OK | MB_ICONERROR);
    return 1;
}

if (lpCmdLine && strstr(lpCmdLine, "-tls-test"))
{
    tls_smoketest();
    WSACleanup();
    DeleteCriticalSection(&g_logLock);
    return 0;
}


    WNDCLASSA wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = APP_CLASS_NAME;
    RegisterClassA(&wc);

    g_hWnd = CreateWindowA(APP_CLASS_NAME, APP_TRAY_TOOLTIP, WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 300, 200,
                           NULL, NULL, hInstance, NULL);

    tray_add_icon();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    stop_tunnels();
    tray_remove_icon();
    free_tunnels();

    WSACleanup();
    DeleteCriticalSection(&g_logLock);
    return 0;
}
