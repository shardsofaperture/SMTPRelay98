# TLSWrap98

TLSWrap98 is a Windows 98 SE system-tray TCP-to-TLS proxy inspired by WinSSLWrap/stunnel. It listens on local plaintext ports and forwards connections to modern TLS 1.2 servers using an embedded TLS library.

## Features
- System tray app (Start/Stop, Open Config, View Log, Exit)
- Multiple tunnels via INI file
- DIRECT_TLS mode (immediate TLS)
- STARTTLS_SMTP mode (SMTP STARTTLS upgrade)
- TLS 1.2 client with optional SNI
- Certificate verification disabled by default
- Text log file

## INI Schema

**Global section** (optional):
- `LogFile` (default `tlswrap98.log`)
- `LogLevel` (0=errors, 1=info, 2=debug)
- `ConnectTimeoutMs` (default 10000)
- `IoTimeoutMs` (default 300000)
- `StartTlsTimeoutMs` (default 10000)

**Tunnel section** (`[tunnel <name>]`):
- `ListenAddr` (default `127.0.0.1`)
- `ListenPort` (required)
- `RemoteHost` (required)
- `RemotePort` (required)
- `Mode` (`DIRECT_TLS` or `STARTTLS_SMTP`)
- `VerifyCert` (`0`/`1`, default `0`)
- `SNI` (optional server name)
- `LogLevel` (override global)

See `config/tlswrap98.ini` for an example.

## Build (Visual C++ 6.0)
1. Create a new **Win32 GUI** project.
2. Add `src/main.cpp` to the project.
3. Add mbedTLS sources to your project (for example under `vendor/mbedtls`).
   - Required components: `library/ssl.c`, `library/ssl_tls.c`, `library/ctr_drbg.c`, `library/entropy.c`, `library/x509_crt.c`, `library/pk.c`, `library/pkparse.c`, `library/asn1parse.c`, `library/md.c`, `library/sha256.c`, `library/bignum.c`, `library/rsa.c`, `library/cipher.c`, `library/cipher_wrap.c`, `library/platform.c`, `library/timing.c`, `library/net_sockets.c`, plus any dependencies mbedTLS requires for TLS 1.2.
4. Add include paths for `vendor/mbedtls/include`.
5. Define `MBEDTLS_CONFIG_FILE="mbedtls_config.h"` and use the provided config at `vendor/mbedTLS/include/mbedtls_config.h` (TLS 1.2 client options are already enabled there).
6. Link against `ws2_32.lib` and `shell32.lib`.

## Notes
- Certificate verification is disabled by default and should be enabled only if you supply CA certificates.
- This project is a hobby-grade compatibility shim, not a hardened security product.
