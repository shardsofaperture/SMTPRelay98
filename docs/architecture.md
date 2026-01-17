# TLSWrap98 Architecture

## Overview
TLSWrap98 is a Windows 98 SE system-tray TCP-to-TLS proxy that provides local plaintext sockets and forwards them to remote TLS 1.2 servers. Each tunnel listens on `ListenAddr:ListenPort`, optionally performs STARTTLS, then establishes TLS 1.2 to the remote host and proxies bytes in both directions.

## Modules
- **Tray/UI (main.cpp)**
  - Creates hidden window and system tray icon.
  - Provides menu: Start/Stop, Open Config, View Log, Exit.
  - Starts/stops tunnel listener threads.
- **Config (main.cpp)**
  - Reads INI file next to the EXE.
  - Enumerates sections named `tunnel <name>`.
  - Loads per-tunnel settings (ports, host, mode, logging, TLS options).
- **Logging (main.cpp)**
  - Appends to `tlswrap98.log` in the EXE directory.
  - Optional log window can be enabled per config (future extension).
- **Network/Tunnel (main.cpp)**
  - Listener thread per tunnel.
  - Connection handler thread per accepted client.
  - Optional STARTTLS for SMTP.
  - TLS handshake with mbedTLS and SNI if configured.
  - Bi-directional proxy loop using `select()` with timeouts.
- **TLS Wrapper (main.cpp)**
  - Minimal adapter around mbedTLS sockets using Winsock.
  - TLS 1.2 client only.
  - Certificate verification disabled by default (configurable).

## Thread Model
- **UI thread**: runs message loop, tray icon, menu actions.
- **Listener thread per tunnel**: blocks on `accept()` and spawns a **connection thread** per client.
- **Connection thread per client**:
  1. Connects to remote server.
  2. Performs STARTTLS (SMTP) if configured.
  3. Performs TLS handshake.
  4. Proxies data until EOF or error.

## IO Model
- Plaintext side uses Winsock `recv()`/`send()`.
- TLS side uses `mbedtls_ssl_read()`/`mbedtls_ssl_write()`.
- A `select()` loop monitors both sockets for readability and enforces idle timeouts.

## Shutdown Behavior
- **Stop** request sets a global shutdown event.
- Listener threads stop accepting and close their listening socket.
- Connection threads check shutdown flag and exit after socket errors or idle timeout.
- UI exits after stopping listeners and cleaning up tray icon.

## Timeouts
- `ConnectTimeoutMs` (global, default 10000) for outbound connect.
- `IoTimeoutMs` (global, default 300000) for idle proxy loop.
- `StartTlsTimeoutMs` (global, default 10000) for STARTTLS response.

## Error Handling
- Errors are logged with severity and tunnel name.
- TLS handshake errors log mbedTLS error codes.
- Proxy loop exits on socket close, TLS close notify, or timeout.
