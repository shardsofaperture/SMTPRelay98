#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include <string.h>
#include <ctype.h>



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
#define ID_TRAY_RELOAD 1005
#define ID_TRAY_MULTIPROFILE 1006
#define ID_TRAY_PROFILE_BASE 2000

#define LOG_ERROR 0
#define LOG_INFO 1
#define LOG_DEBUG 2
#define LOG_TRACE 5

#define MAX_TUNNELS 32

enum TunnelMode
{
    MODE_DIRECT_TLS = 0,
    MODE_STARTTLS_SMTP = 1,
    MODE_SMTP_AUTH_TLS = 2
};

enum AuthMode
{
    AUTH_MODE_AUTO = 0,
    AUTH_MODE_PLAIN = 1,
    AUTH_MODE_LOGIN = 2
};

enum UpstreamTlsMode
{
    TLS_MODE_DIRECT = 0,
    TLS_MODE_STARTTLS = 1
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
    UpstreamTlsMode tlsMode;
    int verifyCert;
    char sni[256];
    int logLevel;
    char upstreamUser[128];
    char upstreamPass[128];
    AuthMode authMode;
    char forceMailFrom[256];
    char forceHeaderFrom[256];
    char logLabel[128];
};

struct TunnelState
{
    TunnelConfig cfg;
    SOCKET listenSock;
    HANDLE thread;
    volatile LONG running;
};

struct ProfileConfig
{
    char name[64];
    char displayName[128];
    char smtpTunnel[64];
    char imapTunnel[64];
    char pop3Tunnel[64];
    bool useAllTunnels;
};

struct ConnectionContext
{
    TunnelConfig cfg;
    SOCKET clientSock;
    SOCKET remoteSock;
};

static GlobalConfig g_config;
static std::vector<TunnelConfig> g_tunnelConfigs;
static std::vector<ProfileConfig> g_profiles;
static std::vector<TunnelState *> g_tunnels;
static HINSTANCE g_hInstance = NULL;
static HWND g_hWnd = NULL;
static volatile LONG g_running = 0;
static volatile LONG g_shutdown = 0;
static CRITICAL_SECTION g_logLock;
static DWORD g_logContextTls = TLS_OUT_OF_INDEXES;
static char g_activeProfile[64] = "";
static bool g_multiProfile = false;

static void set_log_context(const char *label)
{
    if (g_logContextTls != TLS_OUT_OF_INDEXES)
    {
        TlsSetValue(g_logContextTls, (LPVOID)label);
    }
}

static const char *get_log_context()
{
    if (g_logContextTls == TLS_OUT_OF_INDEXES)
    {
        return NULL;
    }
    return (const char *)TlsGetValue(g_logContextTls);
}

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

        char message[1024];
        va_list args;
        va_start(args, fmt);
        _vsnprintf(message, sizeof(message), fmt, args);
        va_end(args);
        message[sizeof(message) - 1] = '\0';

        const char *context = get_log_context();
        if (context && context[0] != '\0')
        {
            fprintf(fp, "[%s] %s\r\n", context, message);
        }
        else
        {
            fprintf(fp, "%s\r\n", message);
        }
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

        char message[1024];
        va_list args;
        va_start(args, fmt);
        _vsnprintf(message, sizeof(message), fmt, args);
        va_end(args);
        message[sizeof(message) - 1] = '\0';

        const char *context = get_log_context();
        if (context && context[0] != '\0')
        {
            fprintf(fp, "[%s] %s\r\n", context, message);
        }
        else
        {
            fprintf(fp, "%s\r\n", message);
        }
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
    if (mode && lstrcmpiA(mode, "SMTP_AUTH_TLS") == 0)
    {
        return MODE_SMTP_AUTH_TLS;
    }
    return MODE_DIRECT_TLS;
}

static UpstreamTlsMode parse_tls_mode(const char *mode)
{
    if (mode && lstrcmpiA(mode, "STARTTLS") == 0)
    {
        return TLS_MODE_STARTTLS;
    }
    return TLS_MODE_DIRECT;
}

static AuthMode parse_auth_mode(const char *mode)
{
    if (!mode || mode[0] == '\0')
    {
        return AUTH_MODE_AUTO;
    }
    if (lstrcmpiA(mode, "plain") == 0)
    {
        return AUTH_MODE_PLAIN;
    }
    if (lstrcmpiA(mode, "login") == 0)
    {
        return AUTH_MODE_LOGIN;
    }
    return AUTH_MODE_AUTO;
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

static void read_ini_string(const char *section, const char *key, const char *fallbackKey,
                            const char *defaultValue, char *out, DWORD outCap,
                            const char *iniPath)
{
    GetPrivateProfileStringA(section, key, defaultValue, out, outCap, iniPath);
    if (out[0] == '\0' && fallbackKey && fallbackKey[0] != '\0')
    {
        GetPrivateProfileStringA(section, fallbackKey, defaultValue, out, outCap, iniPath);
    }
}

static void load_tunnel_config(const char *iniPath, const char *section,
                               const char *tunnelName, TunnelConfig *cfg)
{
    memset(cfg, 0, sizeof(TunnelConfig));
    strncpy(cfg->name, tunnelName, sizeof(cfg->name) - 1);
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

    char tlsModeBuf[64];
    const char *defaultTls = (cfg->mode == MODE_STARTTLS_SMTP) ? "STARTTLS" : "DIRECT_TLS";
    GetPrivateProfileStringA(section, "TlsMode", defaultTls, tlsModeBuf, sizeof(tlsModeBuf),
                             iniPath);
    cfg->tlsMode = parse_tls_mode(tlsModeBuf);

    cfg->logLevel = GetPrivateProfileIntA(section, "LogLevel", g_config.logLevel, iniPath);

    read_ini_string(section, "UpstreamUser", "upstream_user", "",
                    cfg->upstreamUser, sizeof(cfg->upstreamUser), iniPath);
    read_ini_string(section, "UpstreamPass", "upstream_pass", "",
                    cfg->upstreamPass, sizeof(cfg->upstreamPass), iniPath);
    char authModeBuf[32];
    read_ini_string(section, "AuthMode", "auth_mode", "auto",
                    authModeBuf, sizeof(authModeBuf), iniPath);
    cfg->authMode = parse_auth_mode(authModeBuf);

    GetPrivateProfileStringA(section, "ForceMailFrom", "",
                             cfg->forceMailFrom, sizeof(cfg->forceMailFrom), iniPath);
    GetPrivateProfileStringA(section, "ForceHeaderFrom", "",
                             cfg->forceHeaderFrom, sizeof(cfg->forceHeaderFrom), iniPath);

    strncpy(cfg->logLabel, cfg->name, sizeof(cfg->logLabel) - 1);
}

static void free_tunnels()
{
    for (size_t i = 0; i < g_tunnels.size(); ++i)
    {
        delete g_tunnels[i];
    }
    g_tunnels.clear();
}

static void free_loaded_config()
{
    g_tunnelConfigs.clear();
    g_profiles.clear();
}

static void trim_whitespace(char *text)
{
    if (!text || text[0] == '\0')
    {
        return;
    }
    char *end = text + strlen(text) - 1;
    while (end >= text && isspace((unsigned char)*end))
    {
        *end = '\0';
        --end;
    }
    char *start = text;
    while (*start && isspace((unsigned char)*start))
    {
        ++start;
    }
    if (start != text)
    {
        memmove(text, start, strlen(start) + 1);
    }
}

static void load_profile_config(const char *iniPath, const char *section,
                                const char *profileName, ProfileConfig *profile)
{
    memset(profile, 0, sizeof(ProfileConfig));
    strncpy(profile->name, profileName, sizeof(profile->name) - 1);
    GetPrivateProfileStringA(section, "DisplayName", profileName,
                             profile->displayName, sizeof(profile->displayName), iniPath);
    GetPrivateProfileStringA(section, "SmtpTunnel", "",
                             profile->smtpTunnel, sizeof(profile->smtpTunnel), iniPath);
    GetPrivateProfileStringA(section, "ImapTunnel", "",
                             profile->imapTunnel, sizeof(profile->imapTunnel), iniPath);
    GetPrivateProfileStringA(section, "Pop3Tunnel", "",
                             profile->pop3Tunnel, sizeof(profile->pop3Tunnel), iniPath);
    profile->useAllTunnels = false;
    trim_whitespace(profile->smtpTunnel);
    trim_whitespace(profile->imapTunnel);
    trim_whitespace(profile->pop3Tunnel);
}

static const char *profile_display_name(const ProfileConfig *profile)
{
    if (!profile)
    {
        return "";
    }
    if (profile->displayName[0] != '\0')
    {
        return profile->displayName;
    }
    return profile->name;
}

static const char *get_registry_string(const char *valueName, char *out, DWORD outCap)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\TLSWrap98", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return NULL;
    }
    DWORD type = REG_SZ;
    DWORD size = outCap;
    if (RegQueryValueExA(hKey, valueName, NULL, &type, (BYTE *)out, &size) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return NULL;
    }
    out[outCap - 1] = '\0';
    RegCloseKey(hKey);
    return out;
}

static bool get_registry_dword(const char *valueName, DWORD *valueOut)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\TLSWrap98", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return false;
    }
    DWORD type = REG_DWORD;
    DWORD size = sizeof(DWORD);
    DWORD value = 0;
    bool ok = (RegQueryValueExA(hKey, valueName, NULL, &type, (BYTE *)&value, &size) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    if (ok && valueOut)
    {
        *valueOut = value;
    }
    return ok;
}

static void set_registry_string(const char *valueName, const char *value)
{
    HKEY hKey = NULL;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\TLSWrap98", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
    {
        return;
    }
    RegSetValueExA(hKey, valueName, 0, REG_SZ,
                   (const BYTE *)value, (DWORD)strlen(value) + 1);
    RegCloseKey(hKey);
}

static void set_registry_dword(const char *valueName, DWORD value)
{
    HKEY hKey = NULL;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\TLSWrap98", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
    {
        return;
    }
    RegSetValueExA(hKey, valueName, 0, REG_DWORD, (const BYTE *)&value, sizeof(DWORD));
    RegCloseKey(hKey);
}

static void resolve_active_profile()
{
    if (g_profiles.empty())
    {
        return;
    }
    if (g_activeProfile[0] != '\0')
    {
        for (size_t i = 0; i < g_profiles.size(); ++i)
        {
            if (lstrcmpiA(g_profiles[i].name, g_activeProfile) == 0)
            {
                return;
            }
        }
    }
    strncpy(g_activeProfile, g_profiles[0].name, sizeof(g_activeProfile) - 1);
}

static bool load_config()
{
    char iniPath[MAX_PATH];
    build_path(iniPath, sizeof(iniPath), APP_INI_NAME);

    load_default_config();
    load_global_config(iniPath);

    g_activeProfile[0] = '\0';
    g_multiProfile = false;

    char activeProfileBuf[64];
    GetPrivateProfileStringA("global", "ActiveProfile", "", activeProfileBuf,
                             sizeof(activeProfileBuf), iniPath);
    if (activeProfileBuf[0] == '\0')
    {
        char registryProfile[64];
        if (get_registry_string("ActiveProfile", registryProfile, sizeof(registryProfile)))
        {
            strncpy(activeProfileBuf, registryProfile, sizeof(activeProfileBuf) - 1);
        }
    }
    if (activeProfileBuf[0] != '\0')
    {
        strncpy(g_activeProfile, activeProfileBuf, sizeof(g_activeProfile) - 1);
    }

    char multiBuf[16];
    GetPrivateProfileStringA("global", "MultiProfile", "", multiBuf, sizeof(multiBuf), iniPath);
    if (multiBuf[0] == '\0')
    {
        DWORD multiValue = 0;
        if (get_registry_dword("MultiProfile", &multiValue))
        {
            g_multiProfile = (multiValue != 0);
        }
        else
        {
            g_multiProfile = false;
        }
    }
    else
    {
        g_multiProfile = (atoi(multiBuf) != 0);
    }

    char sectionNames[4096];
    DWORD len = GetPrivateProfileSectionNamesA(sectionNames, sizeof(sectionNames), iniPath);
    if (len == 0)
    {
        log_message(LOG_ERROR, "No INI sections found in %s", iniPath);
        return false;
    }

    free_loaded_config();

    const char *ptr = sectionNames;
    while (*ptr)
    {
        if (_strnicmp(ptr, "tunnel ", 7) == 0)
        {
            TunnelConfig cfg;
            char tunnelName[64];
            strncpy(tunnelName, ptr + 7, sizeof(tunnelName) - 1);
            tunnelName[sizeof(tunnelName) - 1] = '\0';
            trim_whitespace(tunnelName);
            if (tunnelName[0] != '\0')
            {
                load_tunnel_config(iniPath, ptr, tunnelName, &cfg);
                if (cfg.listenPort > 0 && cfg.remotePort > 0 && cfg.remoteHost[0] != '\0')
                {
                    g_tunnelConfigs.push_back(cfg);
                }
            }
        }
        else if (_strnicmp(ptr, "profile ", 8) == 0)
        {
            ProfileConfig profile;
            char profileName[64];
            strncpy(profileName, ptr + 8, sizeof(profileName) - 1);
            profileName[sizeof(profileName) - 1] = '\0';
            trim_whitespace(profileName);
            if (profileName[0] != '\0')
            {
                load_profile_config(iniPath, ptr, profileName, &profile);
                g_profiles.push_back(profile);
            }
        }
        ptr += strlen(ptr) + 1;
    }

    if (g_profiles.empty())
    {
        ProfileConfig profile;
        memset(&profile, 0, sizeof(profile));
        strncpy(profile.name, "Default", sizeof(profile.name) - 1);
        strncpy(profile.displayName, "Default", sizeof(profile.displayName) - 1);
        profile.useAllTunnels = true;
        g_profiles.push_back(profile);
    }

    resolve_active_profile();

    if (g_tunnelConfigs.empty())
    {
        log_message(LOG_ERROR, "No valid tunnel definitions found in %s", iniPath);
        return false;
    }

    return true;
}

struct PortKey
{
    char addr[64];
    int port;
};

static const TunnelConfig *find_tunnel_config(const char *name)
{
    if (!name || name[0] == '\0')
    {
        return NULL;
    }
    for (size_t i = 0; i < g_tunnelConfigs.size(); ++i)
    {
        if (lstrcmpiA(g_tunnelConfigs[i].name, name) == 0)
        {
            return &g_tunnelConfigs[i];
        }
    }
    return NULL;
}

static bool port_in_use(const std::vector<PortKey> &usedPorts, const char *addr, int port)
{
    for (size_t i = 0; i < usedPorts.size(); ++i)
    {
        if (usedPorts[i].port == port && lstrcmpiA(usedPorts[i].addr, addr) == 0)
        {
            return true;
        }
    }
    return false;
}

static void add_used_port(std::vector<PortKey> &usedPorts, const char *addr, int port)
{
    PortKey key;
    memset(&key, 0, sizeof(key));
    strncpy(key.addr, addr, sizeof(key.addr) - 1);
    key.port = port;
    usedPorts.push_back(key);
}

static void apply_profile_label(TunnelConfig *cfg, const char *profileName)
{
    if (!cfg)
    {
        return;
    }
    if (profileName && profileName[0] != '\0')
    {
        snprintf(cfg->logLabel, sizeof(cfg->logLabel), "%s/%s", profileName, cfg->name);
    }
    else
    {
        strncpy(cfg->logLabel, cfg->name, sizeof(cfg->logLabel) - 1);
    }
}

static void add_running_tunnel(const TunnelConfig *cfg, const char *profileName)
{
    if (!cfg)
    {
        return;
    }
    TunnelState *state = new TunnelState();
    memset(state, 0, sizeof(TunnelState));
    state->cfg = *cfg;
    apply_profile_label(&state->cfg, profileName);
    state->listenSock = INVALID_SOCKET;
    state->thread = NULL;
    state->running = 0;
    g_tunnels.push_back(state);
}

static void add_profile_tunnels(const ProfileConfig *profile, std::vector<PortKey> &usedPorts)
{
    if (!profile)
    {
        return;
    }
    if (profile->useAllTunnels)
    {
        for (size_t i = 0; i < g_tunnelConfigs.size(); ++i)
        {
            const TunnelConfig *cfg = &g_tunnelConfigs[i];
            if (port_in_use(usedPorts, cfg->listenAddr, cfg->listenPort))
            {
                log_message(LOG_ERROR, "Profile %s: tunnel %s skipped (port in use)",
                            profile->name, cfg->name);
                continue;
            }
            add_used_port(usedPorts, cfg->listenAddr, cfg->listenPort);
            add_running_tunnel(cfg, profile->name);
        }
        return;
    }

    const char *tunnels[3] = { profile->smtpTunnel, profile->imapTunnel, profile->pop3Tunnel };
    for (int i = 0; i < 3; ++i)
    {
        if (tunnels[i][0] == '\0')
        {
            continue;
        }
        const TunnelConfig *cfg = find_tunnel_config(tunnels[i]);
        if (!cfg)
        {
            log_message(LOG_ERROR, "Profile %s references unknown tunnel %s",
                        profile->name, tunnels[i]);
            continue;
        }
        if (port_in_use(usedPorts, cfg->listenAddr, cfg->listenPort))
        {
            log_message(LOG_ERROR, "Profile %s: tunnel %s skipped (port in use)",
                        profile->name, cfg->name);
            continue;
        }
        add_used_port(usedPorts, cfg->listenAddr, cfg->listenPort);
        add_running_tunnel(cfg, profile->name);
    }
}

static const ProfileConfig *find_profile_by_name(const char *name)
{
    if (!name || name[0] == '\0')
    {
        return NULL;
    }
    for (size_t i = 0; i < g_profiles.size(); ++i)
    {
        if (lstrcmpiA(g_profiles[i].name, name) == 0)
        {
            return &g_profiles[i];
        }
    }
    return NULL;
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

struct SmtpRecvBuffer
{
    char data[2048];
    int len;
};

enum
{
    SMTP_MAX_BUFFERED_RCPT = 32
};

struct SmtpSession
{
    bool upstreamConnected;
    bool upstreamTlsOk;
    bool upstreamAuthed;
    bool haveBufferedMailFrom;
    char bufferedMailFrom[512];
    int bufferedRcptCount;
    char bufferedRcpt[SMTP_MAX_BUFFERED_RCPT][512];
};

static int smtp_read_line_buffered(SOCKET sock, char *buffer, int size, int timeoutMs,
                                   SmtpRecvBuffer *state)
{
    if (!state)
    {
        return recv_line(sock, buffer, size, timeoutMs);
    }

    DWORD start = GetTickCount();
    for (;;)
    {
        int i;
        for (i = 0; i < state->len; ++i)
        {
            if (state->data[i] == '\n')
            {
                int lineLen = i + 1;
                int copyLen = lineLen < (size - 1) ? lineLen : (size - 1);
                memcpy(buffer, state->data, copyLen);
                buffer[copyLen] = '\0';
                memmove(state->data, state->data + lineLen, state->len - lineLen);
                state->len -= lineLen;
                return copyLen;
            }
        }

        if (state->len >= (int)sizeof(state->data))
        {
            return -1;
        }

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(sock, &readSet);
        timeval tv;
        int remainMs = timeoutMs;
        if (timeoutMs >= 0)
        {
            DWORD now = GetTickCount();
            int elapsed = (int)(now - start);
            remainMs = timeoutMs - elapsed;
            if (remainMs <= 0)
            {
                return -1;
            }
        }
        tv.tv_sec = remainMs / 1000;
        tv.tv_usec = (remainMs % 1000) * 1000;
        int ret = select(0, &readSet, NULL, NULL, &tv);
        if (ret <= 0)
        {
            return -1;
        }
        int r = recv(sock, state->data + state->len,
                     (int)sizeof(state->data) - state->len, 0);
        if (r <= 0)
        {
            return -1;
        }
        state->len += r;
    }
}

struct LineBuffer
{
    char data[1024];
    int len;
};

static void log_smtp_line(int level, const char *prefix, const char *line)
{
    char clean[1024];
    int i = 0;
    while (line[i] != '\0' && i < (int)sizeof(clean) - 1)
    {
        if (line[i] == '\r' || line[i] == '\n')
        {
            break;
        }
        clean[i] = line[i];
        ++i;
    }
    clean[i] = '\0';
    log_message(level, "%s %s", prefix, clean);
}

static void log_state_transition(int level, const char *state)
{
    log_message(level, "[SMTP] STATE=%s", state);
}

static bool smtp_parse_code(const char *line, int *code, char *sep)
{
    if (!line || !isdigit((unsigned char)line[0]) || !isdigit((unsigned char)line[1]) ||
        !isdigit((unsigned char)line[2]))
    {
        return false;
    }
    if (code)
    {
        *code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    }
    if (sep)
    {
        *sep = line[3];
    }
    return true;
}

static bool read_smtp_reply(SOCKET sock, char *out_buf, int out_cap, int *code,
                            bool *is_multiline_complete, SmtpRecvBuffer *state,
                            int timeoutMs, int logLevel)
{
    int total = 0;
    int expectedCode = 0;
    bool haveCode = false;
    if (is_multiline_complete)
    {
        *is_multiline_complete = false;
    }
    for (;;)
    {
        char line[512];
        int len = smtp_read_line_buffered(sock, line, sizeof(line), timeoutMs, state);
        if (len <= 0)
        {
            return false;
        }
        log_smtp_line(logLevel, "S:", line);
        if (total + len >= out_cap)
        {
            return false;
        }
        memcpy(out_buf + total, line, len);
        total += len;
        out_buf[total] = '\0';

        int lineCode = 0;
        char sep = '\0';
        if (smtp_parse_code(line, &lineCode, &sep))
        {
            if (!haveCode)
            {
                expectedCode = lineCode;
                haveCode = true;
                if (code)
                {
                    *code = expectedCode;
                }
            }
            if (haveCode && lineCode == expectedCode && sep == ' ')
            {
                if (is_multiline_complete)
                {
                    *is_multiline_complete = true;
                }
                return true;
            }
        }
        if (!haveCode && len >= 4 && line[3] != '-')
        {
            if (is_multiline_complete)
            {
                *is_multiline_complete = true;
            }
            return true;
        }
    }
}

static int tls_ssl_recv_line(mbedtls_ssl_context *ssl, char *buffer, int size, int timeoutMs);

static bool read_smtp_reply_tls(mbedtls_ssl_context *ssl, char *out_buf, int out_cap, int *code,
                                bool *is_multiline_complete, int timeoutMs, int logLevel)
{
    int total = 0;
    int expectedCode = 0;
    bool haveCode = false;
    if (is_multiline_complete)
    {
        *is_multiline_complete = false;
    }
    for (;;)
    {
        char line[512];
        int len = tls_ssl_recv_line(ssl, line, sizeof(line), timeoutMs);
        if (len <= 0)
        {
            return false;
        }
        log_smtp_line(logLevel, "S:", line);
        if (total + len >= out_cap)
        {
            return false;
        }
        memcpy(out_buf + total, line, len);
        total += len;
        out_buf[total] = '\0';

        int lineCode = 0;
        char sep = '\0';
        if (smtp_parse_code(line, &lineCode, &sep))
        {
            if (!haveCode)
            {
                expectedCode = lineCode;
                haveCode = true;
                if (code)
                {
                    *code = expectedCode;
                }
            }
            if (haveCode && lineCode == expectedCode && sep == ' ')
            {
                if (is_multiline_complete)
                {
                    *is_multiline_complete = true;
                }
                return true;
            }
        }
        if (!haveCode && len >= 4 && line[3] != '-')
        {
            if (is_multiline_complete)
            {
                *is_multiline_complete = true;
            }
            return true;
        }
    }
}

static int base64_encode(const unsigned char *src, int srcLen, char *dst, int dstCap)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int outLen = 0;
    int i;
    for (i = 0; i < srcLen; i += 3)
    {
        unsigned int b0 = src[i];
        unsigned int b1 = (i + 1 < srcLen) ? src[i + 1] : 0;
        unsigned int b2 = (i + 2 < srcLen) ? src[i + 2] : 0;
        unsigned int triple = (b0 << 16) | (b1 << 8) | b2;
        if (outLen + 4 >= dstCap)
        {
            return -1;
        }
        dst[outLen++] = table[(triple >> 18) & 0x3f];
        dst[outLen++] = table[(triple >> 12) & 0x3f];
        dst[outLen++] = (i + 1 < srcLen) ? table[(triple >> 6) & 0x3f] : '=';
        dst[outLen++] = (i + 2 < srcLen) ? table[triple & 0x3f] : '=';
    }
    if (outLen < dstCap)
    {
        dst[outLen] = '\0';
    }
    return outLen;
}

static const char *find_case_insensitive(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !needle[0])
    {
        return NULL;
    }
    size_t needleLen = strlen(needle);
    for (; *haystack; ++haystack)
    {
        size_t i;
        for (i = 0; i < needleLen; ++i)
        {
            char a = haystack[i];
            char b = needle[i];
            if (a == '\0')
            {
                return NULL;
            }
            if (tolower((unsigned char)a) != tolower((unsigned char)b))
            {
                break;
            }
        }
        if (i == needleLen)
        {
            return haystack;
        }
    }
    return NULL;
}

static bool smtp_host_prefers_login(const char *host)
{
    if (!host)
    {
        return false;
    }
    if (find_case_insensitive(host, "tlen") ||
        find_case_insensitive(host, "wp") ||
        find_case_insensitive(host, "o2"))
    {
        return true;
    }
    return false;
}

static void parse_auth_caps(const char *reply, bool *hasPlain, bool *hasLogin)
{
    if (hasPlain)
    {
        *hasPlain = false;
    }
    if (hasLogin)
    {
        *hasLogin = false;
    }
    if (!reply)
    {
        return;
    }
    const char *ptr = reply;
    while (*ptr)
    {
        const char *lineEnd = strstr(ptr, "\n");
        int lineLen = lineEnd ? (int)(lineEnd - ptr) + 1 : (int)strlen(ptr);
        char line[512];
        int copyLen = lineLen < (int)sizeof(line) - 1 ? lineLen : (int)sizeof(line) - 1;
        memcpy(line, ptr, copyLen);
        line[copyLen] = '\0';
        if (find_case_insensitive(line, "AUTH"))
        {
            if (hasPlain && find_case_insensitive(line, "PLAIN"))
            {
                *hasPlain = true;
            }
            if (hasLogin && find_case_insensitive(line, "LOGIN"))
            {
                *hasLogin = true;
            }
        }
        if (!lineEnd)
        {
            break;
        }
        ptr = lineEnd + 1;
    }
}

static void smtp_session_init(SmtpSession *session)
{
    if (!session)
    {
        return;
    }
    memset(session, 0, sizeof(*session));
}

static bool smtp_buffer_mail_from(SmtpSession *session, const char *line)
{
    if (!session || !line)
    {
        return false;
    }
    strncpy(session->bufferedMailFrom, line, sizeof(session->bufferedMailFrom) - 1);
    session->bufferedMailFrom[sizeof(session->bufferedMailFrom) - 1] = '\0';
    session->haveBufferedMailFrom = true;
    return true;
}

static bool smtp_buffer_rcpt(SmtpSession *session, const char *line)
{
    if (!session || !line)
    {
        return false;
    }
    if (session->bufferedRcptCount >= SMTP_MAX_BUFFERED_RCPT)
    {
        return false;
    }
    strncpy(session->bufferedRcpt[session->bufferedRcptCount], line,
            sizeof(session->bufferedRcpt[session->bufferedRcptCount]) - 1);
    session->bufferedRcpt[session->bufferedRcptCount][sizeof(session->bufferedRcpt[session->bufferedRcptCount]) - 1] = '\0';
    session->bufferedRcptCount++;
    return true;
}

static bool parse_starttls_cap(const char *reply)
{
    if (!reply)
    {
        return false;
    }
    const char *ptr = reply;
    while (*ptr)
    {
        const char *lineEnd = strstr(ptr, "\n");
        int lineLen = lineEnd ? (int)(lineEnd - ptr) + 1 : (int)strlen(ptr);
        char line[512];
        int copyLen = lineLen < (int)sizeof(line) - 1 ? lineLen : (int)sizeof(line) - 1;
        memcpy(line, ptr, copyLen);
        line[copyLen] = '\0';
        if (find_case_insensitive(line, "STARTTLS"))
        {
            return true;
        }
        if (!lineEnd)
        {
            break;
        }
        ptr = lineEnd + 1;
    }
    return false;
}

static void log_client_command_state(int level, const char *line)
{
    if (!line)
    {
        return;
    }
    if (_strnicmp(line, "EHLO", 4) == 0 || _strnicmp(line, "HELO", 4) == 0)
    {
        log_state_transition(level, "EHLO");
    }
    else if (_strnicmp(line, "MAIL", 4) == 0)
    {
        log_state_transition(level, "MAIL");
    }
    else if (_strnicmp(line, "RCPT", 4) == 0)
    {
        log_state_transition(level, "RCPT");
    }
    else if (_strnicmp(line, "DATA", 4) == 0)
    {
        log_state_transition(level, "DATA");
    }
    else if (_strnicmp(line, "QUIT", 4) == 0)
    {
        log_state_transition(level, "QUIT");
    }
    else if (line[0] == '.' && (line[1] == '\r' || line[1] == '\n' || line[1] == '\0'))
    {
        log_state_transition(level, "DOT");
    }
}

static void log_lines_from_buffer(int level, const char *prefix, const char *data, int len,
                                  LineBuffer *state, bool checkClientCommands)
{
    if (!state || !data || len <= 0)
    {
        return;
    }
    int i;
    for (i = 0; i < len; ++i)
    {
        if (state->len < (int)sizeof(state->data) - 1)
        {
            state->data[state->len++] = data[i];
        }
        if (data[i] == '\n')
        {
            state->data[state->len] = '\0';
            log_smtp_line(level, prefix, state->data);
            if (checkClientCommands)
            {
                log_client_command_state(level, state->data);
            }
            state->len = 0;
        }
    }
}

static int tls_ssl_recv_line(mbedtls_ssl_context *ssl, char *buffer, int size, int timeoutMs)
{
    int total = 0;
    DWORD start = GetTickCount();
    while (total < size - 1)
    {
        int ret = mbedtls_ssl_read(ssl, (unsigned char *)buffer + total, 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            if (timeoutMs >= 0)
            {
                DWORD now = GetTickCount();
                if ((int)(now - start) > timeoutMs)
                {
                    return -1;
                }
            }
            Sleep(1);
            continue;
        }
        if (ret == 0)
        {
            return 0;
        }
        if (ret < 0)
        {
            return -1;
        }
        total += ret;
        if (buffer[total - 1] == '\n')
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

static bool send_client_response(SOCKET clientSock, const char *response)
{
    if (!response)
    {
        return false;
    }
    return send_all_plain(clientSock, response, (int)strlen(response));
}

static bool smtp_discard_banner(SOCKET sock, int timeoutMs, int logLevel, SmtpRecvBuffer *state)
{
    char reply[1024];
    int code = 0;
    if (!read_smtp_reply(sock, reply, sizeof(reply), &code, NULL, state, timeoutMs, logLevel))
    {
        return false;
    }
    return true;
}

static bool smtp_forward_response(SOCKET remoteSock, SOCKET clientSock, int timeoutMs, bool *gotOk,
                                  int logLevel, SmtpRecvBuffer *state)
{
    char reply[2048];
    int code = 0;
    bool complete = false;
    if (!read_smtp_reply(remoteSock, reply, sizeof(reply), &code, &complete,
                         state, timeoutMs, logLevel))
    {
        return false;
    }
    if (!send_all_plain(clientSock, reply, (int)strlen(reply)))
    {
        return false;
    }
    if (gotOk)
    {
        *gotOk = (code == 250);
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

static bool tls_send_all(mbedtls_ssl_context *ssl, const char *buffer, int length, int logLevel)
{
    int sent = 0;
    while (sent < length)
    {
        int w = mbedtls_ssl_write(ssl, (const unsigned char *)buffer + sent, length - sent);
        if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }
        if (w <= 0)
        {
            char errbuf[256];
            mbedtls_strerror(w, errbuf, sizeof(errbuf));
            log_message(logLevel, "[SMTP] TLS write failed: ret=%d (-0x%04x) %s",
                        w, (unsigned int)(-w), errbuf);
            return false;
        }
        sent += w;
    }
    return true;
}

static bool smtp_auth_plain_response_tls(mbedtls_ssl_context *ssl, TunnelConfig *cfg,
                                         const char *encoded, int *authCode)
{
    if (!tls_send_all(ssl, encoded, (int)strlen(encoded), cfg->logLevel))
    {
        return false;
    }
    if (!tls_send_all(ssl, "\r\n", 2, cfg->logLevel))
    {
        return false;
    }

    char reply[1024];
    int code = 0;
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.ioTimeoutMs, cfg->logLevel))
    {
        return false;
    }
    if (authCode)
    {
        *authCode = code;
    }
    if (code == 235)
    {
        return true;
    }
    if (code == 530)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH rejected with 530");
    }
    else
    {
        log_message(cfg->logLevel, "[SMTP] AUTH rejected (code=%d)", code);
    }
    return false;
}

static bool smtp_auth_plain_tls(mbedtls_ssl_context *ssl, TunnelConfig *cfg, int *authCode)
{
    if (authCode)
    {
        *authCode = 0;
    }

    unsigned char plainBuf[512];
    int plainLen = 0;
    plainBuf[plainLen++] = '\0';
    strncpy((char *)plainBuf + plainLen, cfg->upstreamUser,
            sizeof(plainBuf) - plainLen - 1);
    plainLen += (int)strlen(cfg->upstreamUser);
    plainBuf[plainLen++] = '\0';
    strncpy((char *)plainBuf + plainLen, cfg->upstreamPass,
            sizeof(plainBuf) - plainLen - 1);
    plainLen += (int)strlen(cfg->upstreamPass);
    plainBuf[plainLen] = '\0';

    char encoded[1024];
    if (base64_encode(plainBuf, plainLen, encoded, sizeof(encoded)) <= 0)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH PLAIN base64 encode failed");
        return false;
    }

    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "AUTH PLAIN %s\r\n", encoded);
    log_message(cfg->logLevel, "[SMTP] AUTH PLAIN sent");
    if (!tls_send_all(ssl, cmd, (int)strlen(cmd), cfg->logLevel))
    {
        return false;
    }

    char reply[1024];
    int code = 0;
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.ioTimeoutMs, cfg->logLevel))
    {
        return false;
    }
    if (code == 334)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH PLAIN challenge received");
        return smtp_auth_plain_response_tls(ssl, cfg, encoded, authCode);
    }
    if (authCode)
    {
        *authCode = code;
    }
    if (code == 235)
    {
        return true;
    }
    if (code == 500 || code == 501 || code == 504)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH PLAIN retrying with two-step flow");
        const char *stepCmd = "AUTH PLAIN\r\n";
        if (!tls_send_all(ssl, stepCmd, (int)strlen(stepCmd), cfg->logLevel))
        {
            return false;
        }
        if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                                 g_config.ioTimeoutMs, cfg->logLevel))
        {
            return false;
        }
        if (code != 334)
        {
            if (authCode)
            {
                *authCode = code;
            }
            log_message(cfg->logLevel, "[SMTP] AUTH PLAIN not accepted (code=%d)", code);
            return false;
        }
        log_message(cfg->logLevel, "[SMTP] AUTH PLAIN challenge received");
        return smtp_auth_plain_response_tls(ssl, cfg, encoded, authCode);
    }
    if (code == 530)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH rejected with 530");
    }
    else
    {
        log_message(cfg->logLevel, "[SMTP] AUTH rejected (code=%d)", code);
    }
    return false;
}

static bool smtp_auth_login_tls(mbedtls_ssl_context *ssl, TunnelConfig *cfg, int *authCode)
{
    if (authCode)
    {
        *authCode = 0;
    }

    const char *cmd = "AUTH LOGIN\r\n";
    log_message(cfg->logLevel, "[SMTP] AUTH LOGIN sent");
    if (!tls_send_all(ssl, cmd, (int)strlen(cmd), cfg->logLevel))
    {
        return false;
    }

    char reply[1024];
    int code = 0;
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.ioTimeoutMs, cfg->logLevel))
    {
        return false;
    }
    if (code != 334)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH LOGIN not accepted (code=%d)", code);
        if (authCode)
        {
            *authCode = code;
        }
        return false;
    }
    log_message(cfg->logLevel, "[SMTP] AUTH LOGIN got username prompt");

    char encodedUser[256];
    if (base64_encode((const unsigned char *)cfg->upstreamUser,
                      (int)strlen(cfg->upstreamUser),
                      encodedUser, sizeof(encodedUser)) <= 0)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH LOGIN user encode failed");
        return false;
    }
    char userCmd[300];
    snprintf(userCmd, sizeof(userCmd), "%s\r\n", encodedUser);
    if (!tls_send_all(ssl, userCmd, (int)strlen(userCmd), cfg->logLevel))
    {
        return false;
    }
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.ioTimeoutMs, cfg->logLevel))
    {
        return false;
    }
    if (code != 334)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH LOGIN user rejected (code=%d)", code);
        if (authCode)
        {
            *authCode = code;
        }
        return false;
    }
    log_message(cfg->logLevel, "[SMTP] AUTH LOGIN got password prompt");

    char encodedPass[256];
    if (base64_encode((const unsigned char *)cfg->upstreamPass,
                      (int)strlen(cfg->upstreamPass),
                      encodedPass, sizeof(encodedPass)) <= 0)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH LOGIN pass encode failed");
        return false;
    }
    char passCmd[300];
    snprintf(passCmd, sizeof(passCmd), "%s\r\n", encodedPass);
    if (!tls_send_all(ssl, passCmd, (int)strlen(passCmd), cfg->logLevel))
    {
        return false;
    }
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.ioTimeoutMs, cfg->logLevel))
    {
        return false;
    }
    if (authCode)
    {
        *authCode = code;
    }
    if (code == 235)
    {
        return true;
    }
    if (code == 530)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH LOGIN rejected with 530");
    }
    else
    {
        log_message(cfg->logLevel, "[SMTP] AUTH LOGIN rejected (code=%d)", code);
    }
    return false;
}

static bool smtp_authenticate_tls(mbedtls_ssl_context *ssl, TunnelConfig *cfg,
                                  const char *ehloReply, int *authCode)
{
    if (authCode)
    {
        *authCode = 0;
    }
    bool hasPlain = false;
    bool hasLogin = false;
    parse_auth_caps(ehloReply, &hasPlain, &hasLogin);

    AuthMode mode = cfg->authMode;
    if (mode == AUTH_MODE_AUTO)
    {
        bool preferLogin = smtp_host_prefers_login(cfg->remoteHost);
        if (preferLogin && hasLogin)
        {
            mode = AUTH_MODE_LOGIN;
        }
        else if (hasPlain)
        {
            mode = AUTH_MODE_PLAIN;
        }
        else if (hasLogin)
        {
            mode = AUTH_MODE_LOGIN;
        }
    }

    if (mode == AUTH_MODE_AUTO)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH not offered by upstream");
        return false;
    }
    if (mode == AUTH_MODE_PLAIN && !hasPlain)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH PLAIN not offered by upstream");
        return false;
    }
    if (mode == AUTH_MODE_LOGIN && !hasLogin)
    {
        log_message(cfg->logLevel, "[SMTP] AUTH LOGIN not offered by upstream");
        return false;
    }

    if (cfg->upstreamUser[0] == '\0' || cfg->upstreamPass[0] == '\0')
    {
        log_message(cfg->logLevel, "[SMTP] missing upstream_user or upstream_pass");
        return false;
    }

    if (mode == AUTH_MODE_PLAIN)
    {
        log_message(cfg->logLevel, "[SMTP] starting upstream AUTH (PLAIN)");
        if (smtp_auth_plain_tls(ssl, cfg, authCode))
        {
            return true;
        }
        if (cfg->authMode == AUTH_MODE_AUTO && hasLogin && authCode && *authCode == 535)
        {
            log_message(cfg->logLevel, "[SMTP] AUTH PLAIN failed, retrying with LOGIN");
            log_message(cfg->logLevel, "[SMTP] starting upstream AUTH (LOGIN)");
            return smtp_auth_login_tls(ssl, cfg, authCode);
        }
        return false;
    }

    if (mode == AUTH_MODE_LOGIN)
    {
        log_message(cfg->logLevel, "[SMTP] starting upstream AUTH (LOGIN)");
        if (smtp_auth_login_tls(ssl, cfg, authCode))
        {
            return true;
        }
        if (cfg->authMode == AUTH_MODE_AUTO && hasPlain && authCode && *authCode == 535)
        {
            log_message(cfg->logLevel, "[SMTP] AUTH LOGIN failed, retrying with PLAIN");
            log_message(cfg->logLevel, "[SMTP] starting upstream AUTH (PLAIN)");
            return smtp_auth_plain_tls(ssl, cfg, authCode);
        }
        return false;
    }

    return false;
}

static const char *smtp_force_mail_from(const TunnelConfig *cfg)
{
    if (!cfg)
    {
        return NULL;
    }
    if (cfg->forceMailFrom[0] != '\0')
    {
        return cfg->forceMailFrom;
    }
    if (cfg->mode == MODE_SMTP_AUTH_TLS && cfg->upstreamUser[0] != '\0')
    {
        return cfg->upstreamUser;
    }
    return NULL;
}

static bool smtp_build_mail_from_line(const char *line, const char *forced,
                                      char *out, int outCap)
{
    if (!line || !forced || forced[0] == '\0')
    {
        return false;
    }
    const char *fromPtr = find_case_insensitive(line, "FROM:");
    if (!fromPtr)
    {
        return false;
    }

    const char *addrStart = fromPtr + 5;
    while (*addrStart == ' ' || *addrStart == '\t')
    {
        ++addrStart;
    }

    const char *addrEnd = addrStart;
    if (*addrStart == '<')
    {
        const char *gt = strchr(addrStart, '>');
        if (gt)
        {
            addrEnd = gt + 1;
        }
    }
    if (addrEnd == addrStart)
    {
        while (*addrEnd && *addrEnd != ' ' && *addrEnd != '\t' &&
               *addrEnd != '\r' && *addrEnd != '\n')
        {
            ++addrEnd;
        }
    }

    const char *tail = addrEnd;
    while (*tail == ' ' || *tail == '\t')
    {
        ++tail;
    }
    const char *eol = strstr(line, "\r\n");
    if (!eol)
    {
        eol = strstr(line, "\n");
    }
    const char *lineEnd = eol ? eol : line + strlen(line);
    int tailLen = (tail < lineEnd) ? (int)(lineEnd - tail) : 0;

    int written = snprintf(out, outCap, "MAIL FROM:<%s>", forced);
    if (written <= 0 || written >= outCap)
    {
        return false;
    }
    if (tailLen > 0)
    {
        if (written + 1 + tailLen >= outCap)
        {
            return false;
        }
        out[written++] = ' ';
        memcpy(out + written, tail, tailLen);
        written += tailLen;
        out[written] = '\0';
    }
    if (written + 2 >= outCap)
    {
        return false;
    }
    out[written++] = '\r';
    out[written++] = '\n';
    out[written] = '\0';
    return true;
}

static bool smtp_send_and_forward_reply(SOCKET clientSock, mbedtls_ssl_context *ssl,
                                        const char *line, int len, int logLevel, int timeoutMs)
{
    if (!tls_send_all(ssl, line, len, logLevel))
    {
        return false;
    }
    char reply[2048];
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), NULL, NULL, timeoutMs, LOG_DEBUG))
    {
        return false;
    }
    if (!send_all_plain(clientSock, reply, (int)strlen(reply)))
    {
        return false;
    }
    return true;
}

static bool smtp_replay_buffered_commands(SmtpSession *session, SOCKET clientSock,
                                          mbedtls_ssl_context *ssl, TunnelConfig *cfg)
{
    if (!session || !cfg)
    {
        return false;
    }

    if (session->haveBufferedMailFrom)
    {
        log_message(cfg->logLevel, "[SMTP] replaying buffered MAIL FROM");
        char mailLine[512];
        const char *forcedMailFrom = smtp_force_mail_from(cfg);
        if (forcedMailFrom &&
            smtp_build_mail_from_line(session->bufferedMailFrom, forcedMailFrom,
                                      mailLine, sizeof(mailLine)))
        {
            log_message(cfg->logLevel, "[SMTP] MAIL FROM rewritten to %s", forcedMailFrom);
        }
        else
        {
            strncpy(mailLine, session->bufferedMailFrom, sizeof(mailLine) - 1);
            mailLine[sizeof(mailLine) - 1] = '\0';
        }
        if (!smtp_send_and_forward_reply(clientSock, ssl, mailLine,
                                         (int)strlen(mailLine), cfg->logLevel,
                                         g_config.ioTimeoutMs))
        {
            return false;
        }
        session->haveBufferedMailFrom = false;
    }

    if (session->bufferedRcptCount > 0)
    {
        int i;
        log_message(cfg->logLevel, "[SMTP] replaying buffered RCPT");
        for (i = 0; i < session->bufferedRcptCount; ++i)
        {
            const char *rcptLine = session->bufferedRcpt[i];
            if (!smtp_send_and_forward_reply(clientSock, ssl, rcptLine,
                                             (int)strlen(rcptLine), cfg->logLevel,
                                             g_config.ioTimeoutMs))
            {
                return false;
            }
        }
        session->bufferedRcptCount = 0;
    }

    return true;
}

static bool smtp_connect_upstream(TunnelConfig *cfg, SOCKET *remoteSockOut,
                                  mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf,
                                  mbedtls_ctr_drbg_context *ctr_drbg,
                                  mbedtls_entropy_context *entropy, mbedtls_x509_crt *cacert,
                                  char *ehloReply, int ehloReplyCap, int *authCodeOut)
{
    if (!cfg || !remoteSockOut)
    {
        return false;
    }
    if (authCodeOut)
    {
        *authCodeOut = 0;
    }

    *remoteSockOut = connect_with_timeout(cfg->remoteHost, cfg->remotePort,
                                          g_config.connectTimeoutMs);
    if (*remoteSockOut == INVALID_SOCKET)
    {
        log_message(cfg->logLevel, "%s: connect failed", cfg->name);
        return false;
    }

    log_state_transition(cfg->logLevel, "CONNECT");

    char reply[2048];
    int code = 0;
    const char *ehlo = "EHLO localhost\r\n";
    if (cfg->tlsMode == TLS_MODE_STARTTLS)
    {
        SmtpRecvBuffer remoteState;
        memset(&remoteState, 0, sizeof(remoteState));
        if (!read_smtp_reply(*remoteSockOut, reply, sizeof(reply), &code, NULL,
                             &remoteState, g_config.startTlsTimeoutMs, LOG_DEBUG))
        {
            log_message(cfg->logLevel, "[SMTP] failed to read upstream banner");
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }

        if (!send_all_plain(*remoteSockOut, ehlo, (int)strlen(ehlo)))
        {
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }
        log_state_transition(cfg->logLevel, "EHLO");
        if (!read_smtp_reply(*remoteSockOut, reply, sizeof(reply), &code, NULL,
                             &remoteState, g_config.startTlsTimeoutMs, LOG_DEBUG))
        {
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }
        if (code != 250)
        {
            log_message(cfg->logLevel, "[SMTP] upstream EHLO rejected (code=%d)", code);
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }
        if (!parse_starttls_cap(reply))
        {
            log_message(cfg->logLevel, "[SMTP] upstream did not advertise STARTTLS");
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }

        const char *starttls = "STARTTLS\r\n";
        if (!send_all_plain(*remoteSockOut, starttls, (int)strlen(starttls)))
        {
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }
        log_state_transition(cfg->logLevel, "STARTTLS");
        if (!read_smtp_reply(*remoteSockOut, reply, sizeof(reply), &code, NULL,
                             &remoteState, g_config.startTlsTimeoutMs, LOG_DEBUG))
        {
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }
        if (code != 220)
        {
            log_message(cfg->logLevel, "[SMTP] STARTTLS rejected (code=%d)", code);
            closesocket(*remoteSockOut);
            *remoteSockOut = INVALID_SOCKET;
            return false;
        }
    }

    if (!tls_handshake(remoteSockOut, cfg, ssl, conf, ctr_drbg, entropy, cacert))
    {
        closesocket(*remoteSockOut);
        *remoteSockOut = INVALID_SOCKET;
        return false;
    }
    log_state_transition(cfg->logLevel, "TLS_OK");

    if (cfg->tlsMode == TLS_MODE_DIRECT)
    {
        if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                                 g_config.startTlsTimeoutMs, LOG_DEBUG))
        {
            log_message(cfg->logLevel, "[SMTP] failed to read upstream banner");
            return false;
        }
    }

    if (!tls_send_all(ssl, ehlo, (int)strlen(ehlo), cfg->logLevel))
    {
        log_message(cfg->logLevel, "[SMTP] post-TLS EHLO write failed");
        return false;
    }
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.startTlsTimeoutMs, LOG_DEBUG))
    {
        log_message(cfg->logLevel, "[SMTP] post-TLS EHLO read failed");
        return false;
    }
    if (code != 250)
    {
        log_message(cfg->logLevel, "[SMTP] post-TLS EHLO rejected (code=%d)", code);
        return false;
    }
    log_state_transition(cfg->logLevel, "EHLO2");
    if (ehloReply && ehloReplyCap > 0)
    {
        strncpy(ehloReply, reply, ehloReplyCap - 1);
        ehloReply[ehloReplyCap - 1] = '\0';
    }

    int authCode = 0;
    if (!smtp_authenticate_tls(ssl, cfg, reply, &authCode))
    {
        if (authCodeOut)
        {
            *authCodeOut = authCode;
        }
        log_message(cfg->logLevel, "[SMTP] upstream authentication failed");
        return false;
    }
    if (authCodeOut)
    {
        *authCodeOut = authCode;
    }
    log_state_transition(cfg->logLevel, "AUTH_OK");

    return true;
}

static bool smtp_ensure_upstream_authed(SmtpSession *session, TunnelConfig *cfg,
                                        SOCKET *remoteSock, mbedtls_ssl_context *ssl,
                                        mbedtls_ssl_config *conf,
                                        mbedtls_ctr_drbg_context *ctr_drbg,
                                        mbedtls_entropy_context *entropy,
                                        mbedtls_x509_crt *cacert,
                                        int *authCodeOut)
{
    if (!session || !cfg)
    {
        return false;
    }
    if (session->upstreamAuthed)
    {
        return true;
    }

    char ehloReply[2048];
    if (!smtp_connect_upstream(cfg, remoteSock, ssl, conf, ctr_drbg, entropy, cacert,
                               ehloReply, sizeof(ehloReply), authCodeOut))
    {
        return false;
    }
    session->upstreamConnected = true;
    session->upstreamTlsOk = true;
    session->upstreamAuthed = true;
    return true;
}

static bool smtp_handle_data(SOCKET clientSock, mbedtls_ssl_context *ssl, TunnelConfig *cfg,
                             SmtpRecvBuffer *clientState)
{
    char reply[2048];
    int code = 0;
    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.ioTimeoutMs, LOG_DEBUG))
    {
        return false;
    }
    if (!send_all_plain(clientSock, reply, (int)strlen(reply)))
    {
        return false;
    }
    if (code != 354)
    {
        return true;
    }

    bool inHeaders = true;
    bool skipFromContinuation = false;
    for (;;)
    {
        char line[1024];
        int len = smtp_read_line_buffered(clientSock, line, sizeof(line),
                                          g_config.ioTimeoutMs, clientState);
        if (len <= 0)
        {
            return false;
        }
        log_smtp_line(LOG_DEBUG, "C:", line);
        if (line[0] == '.' && (line[1] == '\r' || line[1] == '\n' || line[1] == '\0'))
        {
            log_state_transition(cfg->logLevel, "DOT");
            if (!tls_send_all(ssl, line, len, cfg->logLevel))
            {
                return false;
            }
            break;
        }

        if (inHeaders)
        {
            if (line[0] == '\r' || line[0] == '\n')
            {
                inHeaders = false;
                skipFromContinuation = false;
            }
            else if (skipFromContinuation && (line[0] == ' ' || line[0] == '\t'))
            {
                continue;
            }
            else
            {
                skipFromContinuation = false;
                if (cfg->forceHeaderFrom[0] != '\0' &&
                    _strnicmp(line, "From:", 5) == 0)
                {
                    char rewritten[512];
                    snprintf(rewritten, sizeof(rewritten), "From: %s\r\n",
                             cfg->forceHeaderFrom);
                    len = (int)strlen(rewritten);
                    strncpy(line, rewritten, sizeof(line) - 1);
                    line[sizeof(line) - 1] = '\0';
                    skipFromContinuation = true;
                }
            }
        }

        if (line[0] == '.')
        {
            if (!tls_send_all(ssl, ".", 1, cfg->logLevel))
            {
                return false;
            }
        }
        if (!tls_send_all(ssl, line, len, cfg->logLevel))
        {
            return false;
        }
    }

    if (!read_smtp_reply_tls(ssl, reply, sizeof(reply), &code, NULL,
                             g_config.ioTimeoutMs, LOG_DEBUG))
    {
        return false;
    }
    if (!send_all_plain(clientSock, reply, (int)strlen(reply)))
    {
        return false;
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

    set_log_context(cfg.logLabel);

    if (cfg.mode == MODE_STARTTLS_SMTP || cfg.mode == MODE_SMTP_AUTH_TLS)
    {
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;
        mbedtls_x509_crt cacert;
        bool tlsReady = false;
        bool greeted = false;
        SmtpSession session;
        smtp_session_init(&session);

        SmtpRecvBuffer clientState;
        memset(&clientState, 0, sizeof(clientState));

        for (;;)
        {
            char line[1024];
            int len = smtp_read_line_buffered(clientSock, line, sizeof(line),
                                              g_config.ioTimeoutMs, &clientState);
            if (len <= 0)
            {
                break;
            }
            log_smtp_line(LOG_DEBUG, "C:", line);
            log_client_command_state(cfg.logLevel, line);

            if (_strnicmp(line, "EHLO", 4) == 0 || _strnicmp(line, "HELO", 4) == 0)
            {
                const char *capabilities =
                    "250-localhost\r\n"
                    "250-PIPELINING\r\n"
                    "250-8BITMIME\r\n"
                    "250-SIZE 10485760\r\n"
                    "250 HELP\r\n";
                greeted = true;
                if (!send_client_response(clientSock, capabilities))
                {
                    break;
                }
                continue;
            }

            if (_strnicmp(line, "NOOP", 4) == 0)
            {
                if (!send_client_response(clientSock, "250 OK\r\n"))
                {
                    break;
                }
                continue;
            }

            if (_strnicmp(line, "RSET", 4) == 0)
            {
                if (session.upstreamConnected)
                {
                    if (!tls_send_all(&ssl, line, len, cfg.logLevel))
                    {
                        break;
                    }
                    char reply[2048];
                    if (!read_smtp_reply_tls(&ssl, reply, sizeof(reply), NULL, NULL,
                                             g_config.ioTimeoutMs, LOG_DEBUG))
                    {
                        break;
                    }
                    if (!send_all_plain(clientSock, reply, (int)strlen(reply)))
                    {
                        break;
                    }
                }
                else if (!send_client_response(clientSock, "250 OK\r\n"))
                {
                    break;
                }
                continue;
            }

            if (_strnicmp(line, "QUIT", 4) == 0)
            {
                log_state_transition(cfg.logLevel, "QUIT");
                send_client_response(clientSock, "221 Bye\r\n");
                if (session.upstreamConnected)
                {
                    tls_send_all(&ssl, "QUIT\r\n", 6, cfg.logLevel);
                }
                break;
            }

            if (_strnicmp(line, "STARTTLS", 8) == 0)
            {
                log_message(cfg.logLevel, "[SMTP] local STARTTLS requested but not available");
                send_client_response(clientSock, "454 TLS not available\r\n");
                continue;
            }

            if (!greeted)
            {
                if (!send_client_response(clientSock, "503 Send EHLO/HELO first\r\n"))
                {
                    break;
                }
                continue;
            }

            if (_strnicmp(line, "MAIL", 4) == 0 || _strnicmp(line, "RCPT", 4) == 0 ||
                _strnicmp(line, "DATA", 4) == 0)
            {
                bool isMail = (_strnicmp(line, "MAIL", 4) == 0);
                bool isRcpt = (_strnicmp(line, "RCPT", 4) == 0);
                bool isData = (_strnicmp(line, "DATA", 4) == 0);

                if (cfg.mode == MODE_SMTP_AUTH_TLS && !session.upstreamAuthed)
                {
                    // O2 fix: AUTH before MAIL FROM.
                    if (isMail)
                    {
                        log_message(cfg.logLevel, "[SMTP] buffering MAIL FROM until AUTH");
                        smtp_buffer_mail_from(&session, line);
                    }
                    else if (isRcpt)
                    {
                        log_message(cfg.logLevel, "[SMTP] buffering RCPT TO until AUTH");
                        if (!smtp_buffer_rcpt(&session, line))
                        {
                            send_client_response(clientSock, "451 Too many recipients\r\n");
                            continue;
                        }
                    }
                    else if (isData)
                    {
                        log_message(cfg.logLevel, "[SMTP] DATA received before AUTH");
                    }

                    int authCode = 0;
                    if (!smtp_ensure_upstream_authed(&session, &cfg, &remoteSock, &ssl,
                                                     &conf, &ctr_drbg, &entropy, &cacert,
                                                     &authCode))
                    {
                        if (authCode == 535 || authCode == 530)
                        {
                            send_client_response(clientSock, "535 Authentication failed\r\n");
                        }
                        else
                        {
                            send_client_response(clientSock, "451 Upstream unavailable\r\n");
                        }
                        break;
                    }
                    tlsReady = true;

                    if (!smtp_replay_buffered_commands(&session, clientSock, &ssl, &cfg))
                    {
                        break;
                    }

                    if (!isData)
                    {
                        continue;
                    }
                }

                if (!session.upstreamConnected)
                {
                    char ehloReply[2048];
                    int authCode = 0;
                    if (!smtp_connect_upstream(&cfg, &remoteSock, &ssl, &conf, &ctr_drbg,
                                               &entropy, &cacert, ehloReply,
                                               sizeof(ehloReply), &authCode))
                    {
                        if (authCode == 535 || authCode == 530)
                        {
                            send_client_response(clientSock, "535 Authentication failed\r\n");
                        }
                        else
                        {
                            send_client_response(clientSock, "451 Upstream unavailable\r\n");
                        }
                        break;
                    }
                    tlsReady = true;
                    session.upstreamConnected = true;
                    session.upstreamTlsOk = true;
                    session.upstreamAuthed = true;
                }

                if (isMail)
                {
                    log_state_transition(cfg.logLevel, "MAIL");
                }
                if (isRcpt)
                {
                    log_state_transition(cfg.logLevel, "RCPT");
                }
                if (isData)
                {
                    log_state_transition(cfg.logLevel, "DATA");
                }

                const char *forcedMailFrom = smtp_force_mail_from(&cfg);
                if (isMail && forcedMailFrom)
                {
                    char rewritten[512];
                    if (smtp_build_mail_from_line(line, forcedMailFrom,
                                                  rewritten, sizeof(rewritten)))
                    {
                        // O2.PL rejects messages when AUTH identity and MAIL FROM disagree (SPF alignment).
                        log_message(cfg.logLevel, "[SMTP] MAIL FROM rewritten to %s",
                                    forcedMailFrom);
                        len = (int)strlen(rewritten);
                        strncpy(line, rewritten, sizeof(line) - 1);
                        line[sizeof(line) - 1] = '\0';
                    }
                }

                if (isData)
                {
                    if (!tls_send_all(&ssl, line, len, cfg.logLevel))
                    {
                        break;
                    }
                    if (!smtp_handle_data(clientSock, &ssl, &cfg, &clientState))
                    {
                        break;
                    }
                }
                else
                {
                    if (!smtp_send_and_forward_reply(clientSock, &ssl, line, len,
                                                     cfg.logLevel, g_config.ioTimeoutMs))
                    {
                        break;
                    }
                }
                continue;
            }

            send_client_response(clientSock, "500 Command unrecognized\r\n");
        }

        if (tlsReady)
        {
            tls_cleanup(&ssl, &conf, &ctr_drbg, &entropy, &cacert);
        }
        if (remoteSock != INVALID_SOCKET)
        {
            closesocket(remoteSock);
        }
        closesocket(clientSock);
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
    set_log_context(state->cfg.logLabel);

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
        if (state->cfg.mode == MODE_STARTTLS_SMTP || state->cfg.mode == MODE_SMTP_AUTH_TLS)
        {
            const char *banner = "220 localhost TLSWrap98 ready\r\n";
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

    free_tunnels();

    std::vector<PortKey> usedPorts;
    if (g_multiProfile)
    {
        for (size_t i = 0; i < g_profiles.size(); ++i)
        {
            add_profile_tunnels(&g_profiles[i], usedPorts);
        }
    }
    else
    {
        const ProfileConfig *profile = find_profile_by_name(g_activeProfile);
        if (!profile && !g_profiles.empty())
        {
            profile = &g_profiles[0];
        }
        if (profile)
        {
            add_profile_tunnels(profile, usedPorts);
        }
    }

    if (g_tunnels.empty())
    {
        MessageBoxA(g_hWnd, "No valid tunnels found for selected profile(s).",
                    "TLSWrap98", MB_OK | MB_ICONERROR);
        return;
    }

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
    free_tunnels();
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

static void persist_active_profile()
{
    char iniPath[MAX_PATH];
    build_path(iniPath, sizeof(iniPath), APP_INI_NAME);
    WritePrivateProfileStringA("global", "ActiveProfile", g_activeProfile, iniPath);
    set_registry_string("ActiveProfile", g_activeProfile);
}

static void persist_multi_profile()
{
    char iniPath[MAX_PATH];
    char valueBuf[8];
    build_path(iniPath, sizeof(iniPath), APP_INI_NAME);
    snprintf(valueBuf, sizeof(valueBuf), "%d", g_multiProfile ? 1 : 0);
    WritePrivateProfileStringA("global", "MultiProfile", valueBuf, iniPath);
    set_registry_dword("MultiProfile", g_multiProfile ? 1 : 0);
}

static void switch_active_profile(const char *profileName)
{
    if (!profileName || profileName[0] == '\0')
    {
        return;
    }
    strncpy(g_activeProfile, profileName, sizeof(g_activeProfile) - 1);
    persist_active_profile();
    if (g_running && !g_multiProfile)
    {
        stop_tunnels();
        start_tunnels();
    }
}

static void toggle_multi_profile()
{
    g_multiProfile = !g_multiProfile;
    persist_multi_profile();
    if (g_running)
    {
        stop_tunnels();
        start_tunnels();
    }
}

static void reload_config_and_restart()
{
    if (g_running)
    {
        stop_tunnels();
        start_tunnels();
    }
    else
    {
        load_config();
    }
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

    HMENU hProfiles = CreatePopupMenu();
    if (hProfiles)
    {
        for (size_t i = 0; i < g_profiles.size(); ++i)
        {
            const ProfileConfig *profile = &g_profiles[i];
            UINT flags = MF_STRING;
            AppendMenuA(hProfiles, flags, ID_TRAY_PROFILE_BASE + (UINT)i,
                        profile_display_name(profile));
        }
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hProfiles, "Profiles");
        if (!g_profiles.empty())
        {
            for (size_t i = 0; i < g_profiles.size(); ++i)
            {
                if (lstrcmpiA(g_profiles[i].name, g_activeProfile) == 0)
                {
                    CheckMenuRadioItem(hProfiles, ID_TRAY_PROFILE_BASE,
                                       ID_TRAY_PROFILE_BASE + (UINT)g_profiles.size() - 1,
                                       ID_TRAY_PROFILE_BASE + (UINT)i, MF_BYCOMMAND);
                    break;
                }
            }
        }
    }

    AppendMenuA(hMenu, MF_STRING | (g_multiProfile ? MF_CHECKED : 0),
                ID_TRAY_MULTIPROFILE, "Run all profiles (MultiProfile)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_STARTSTOP, g_running ? "Stop" : "Start");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_OPENCFG, "Open Config");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_VIEWLOG, "View Log");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_RELOAD, "Reload INI");
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
        case ID_TRAY_RELOAD:
            reload_config_and_restart();
            return 0;
        case ID_TRAY_MULTIPROFILE:
            toggle_multi_profile();
            return 0;
        case ID_TRAY_EXIT:
            PostQuitMessage(0);
            return 0;
        }
        if (LOWORD(wParam) >= ID_TRAY_PROFILE_BASE &&
            LOWORD(wParam) < ID_TRAY_PROFILE_BASE + (int)g_profiles.size())
        {
            size_t index = (size_t)(LOWORD(wParam) - ID_TRAY_PROFILE_BASE);
            if (index < g_profiles.size())
            {
                switch_active_profile(g_profiles[index].name);
            }
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
g_logContextTls = TlsAlloc();
if (g_logContextTls == TLS_OUT_OF_INDEXES) {
	MessageBoxA(NULL, "TlsAlloc failed", "TLSWrap98", MB_OK | MB_ICONERROR);
	return 1;
}
set_log_context("main");

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
    if (g_logContextTls != TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_logContextTls);
        g_logContextTls = TLS_OUT_OF_INDEXES;
    }
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
    load_config();

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
    if (g_logContextTls != TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_logContextTls);
        g_logContextTls = TLS_OUT_OF_INDEXES;
    }
    return 0;
}
