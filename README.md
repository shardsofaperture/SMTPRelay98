# TLSWrap98 / SMTPRelay98

A **Windows 98–compatible SMTP submission relay** that allows legacy mail clients (Outlook 98/2000, etc.) to send mail through **modern SMTP servers using TLS 1.2**.

This project bridges a hard gap: classic Win9x software expects plaintext SMTP, while modern servers require STARTTLS + SMTP AUTH on port 587. TLSWrap98 performs that translation locally, in-process, without relying on Schannel, KernelEx, or external proxies.

---

## What This Is

TLSWrap98 is a **localhost SMTP submission server**.

```
Outlook / Legacy Client (plaintext SMTP)
            |
            v
     TLSWrap98 (localhost)
            |
            v
   STARTTLS + AUTH (TLS 1.2)
            |
            v
 Modern SMTP Submission Server (587)
```

### Design Principles

- Local side is **always plaintext**
- TLS is **only used upstream**
- SMTP AUTH is handled **by TLSWrap98**, not the mail client
- Designed and tested on **real Windows 98 / Pentium III hardware**
- Built with **Microsoft Visual C++ 6.0**
- Uses **mbedTLS 2.16.x** (Apache 2.0)

MercuryC and other intermediate SMTP servers are **not required**.  
They were an earlier, more fragile workaround and are now obsolete.

---

## Features

- SMTP submission relay (port 587 upstream)
- STARTTLS with TLS 1.2
- SMTP AUTH support:
  - `AUTH PLAIN`
  - `AUTH LOGIN`
  - automatic selection based on server capabilities
- Correct handling of:
  - multiline SMTP replies (`250-` / `250 `)
  - EHLO capability parsing
  - DATA dot-stuffing
- INI-based configuration
- Detailed SMTP transcript logging
- Windows 98 tray application:
  - start / stop
  - open configuration
  - view log

---

## Non-Goals / Intentional Limitations

- No local TLS / STARTTLS support (by design)
- No POP3 or IMAP proxying
- No mail storage, spooling, or queueing
- No Kerberos, OAuth, or modern auth schemes
- No strong credential protection beyond basic obfuscation

This is a **submission bridge**, not a full MTA.

---

## Build Requirements

- Windows 98 or 98 SE
- Microsoft Visual C++ 6.0
- WinSock 2
- mbedTLS 2.16.x (statically linked)
- Pentium-class CPU (no SSE2 assumptions)

### Notes on mbedTLS

mbedTLS is built with a reduced feature set suitable for Win9x:

- TLS 1.2 enabled
- SNI enabled
- X.509 certificate validation enabled
- No OS crypto dependencies
- No Schannel usage

---

## Configuration (`tlswrap98.ini`)

Minimal example:

```ini
[global]
LogLevel=2
ConnectTimeoutMs=10000
IoTimeoutMs=300000
StartTlsTimeoutMs=10000

[tunnel smtp]
ListenAddr=127.0.0.1
ListenPort=25
RemoteHost=smtp.example.com
RemotePort=587
Mode=STARTTLS_SMTP
SNI=smtp.example.com
VerifyCert=1

upstream_user=your@email.com
upstream_pass=yourpassword
auth_mode=auto
```

### Authentication Modes

- `auto` (default): prefer `AUTH PLAIN`, fallback to `AUTH LOGIN`
- `plain`: force `AUTH PLAIN`
- `login`: force `AUTH LOGIN`

---

## Outlook Configuration

Configure Outlook to send mail via localhost:

- **Outgoing mail server:** `127.0.0.1`
- **Port:** `25` (or the configured `ListenPort`)
- **Do NOT enable SSL/TLS**
- **Do NOT enable SMTP authentication**

TLSWrap98 handles TLS and authentication upstream automatically.

---

## SMTP Behavior (Important)

### Local EHLO Response

TLSWrap98 intentionally **does not advertise `STARTTLS` or `AUTH`** to the local client.

Example response:

```
250-localhost
250-PIPELINING
250-8BITMIME
250-SIZE 10485760
250 HELP
```

This prevents legacy clients from attempting TLS against localhost.

If the client sends `STARTTLS` anyway, TLSWrap98 responds with:

```
454 TLS not available
```

---

### Upstream SMTP Flow

All upstream submissions follow this sequence:

1. TCP connect  
2. `EHLO`  
3. `STARTTLS`  
4. TLS handshake  
5. `EHLO` (post-TLS)  
6. `AUTH`  
7. `MAIL FROM`  
8. `RCPT TO`  
9. `DATA`  

---

## Logging

All activity is written to `tlswrap98.log`.

Logs include:

- Client commands (`C:`)
- Upstream responses (`S:`)
- State transitions:
  - `CONNECT`
  - `EHLO`
  - `STARTTLS`
  - `TLS_OK`
  - `EHLO2`
  - `AUTH_OK`
  - `MAIL`
  - `RCPT`
  - `DATA`
  - `DOT`
  - `QUIT`

This makes SMTP-level debugging feasible on Windows 98.

---

## Security Notes

- Credentials are stored in plaintext in the INI file
- Threat model assumes a trusted local machine
- Focus is compatibility and functionality, not modern credential security

Potential future enhancements:

- Pass-through SMTP AUTH
- Prompt-on-startup credentials (memory-only)
- Simple encrypted credential storage

---

## Licensing

### TLSWrap98 / SMTPRelay98

MIT License. See `LICENSE`.

### mbedTLS

mbedTLS is licensed under the **Apache License 2.0**.

- All files under `vendor/mbedTLS/` remain Apache 2.0
- All other source files are MIT

License texts are included in the `license/` directory.

---

## Status

✔ Working  
✔ Confirmed TLS 1.2 upstream  
✔ Successfully sends mail from Outlook on Windows 98  

This is a **finished, functional SMTP submission bridge**.

---

## Rationale

Old software didn’t stop working.  
The network changed.  

This bridges the gap.

---

## Visual C++ 6.0 Build Configuration Details (Path-Independent)

This project includes **precompiled mbedTLS static libraries** and is intended to be built with  
**Microsoft Visual C++ 6.0** targeting **Windows 98**.

All paths below are **project-relative**.  
VC6 resolves relative paths relative to the project file (`.dsp`) location.

---

### Preprocessor Definitions

```
WIN32
NDEBUG
_WINDOWS
_MBCS
SIZE_MAX=0xFFFFFFFFu
```

- `SIZE_MAX` is not provided by VC6 and must be defined manually.
- `_MBCS` forces ANSI/MBCS APIs.
- `NDEBUG` disables debug-only checks in Release builds.

---

### Include Directories

```
.\src
.\vendor\mbedTLS\include
```

Expected layout:

```
src\
vendor\
  mbedTLS\
    include\
    lib\
```

---

### Compiler Flags (Release)

```
/nologo
/ML
/W3
/GX
/O2
/I ".\src"
/I ".\vendor\mbedTLS\include"
/D "WIN32"
/D "NDEBUG"
/D "_WINDOWS"
/D "_MBCS"
/D SIZE_MAX=0xFFFFFFFFu
/Fp"Release\smtprealy98.pch"
/YX
/Fo"Release\"
/Fd"Release\"
/FD
/c
```

- `/ML` is required (static CRT).
- Do not use `/MD` or `/MDd`.
- No SSE2 or Pentium-4-only flags are used.

---

### Linker Input Libraries

```
kernel32.lib
user32.lib
gdi32.lib
winspool.lib
comdlg32.lib
advapi32.lib
shell32.lib
ole32.lib
oleaut32.lib
uuid.lib
odbc32.lib
odbccp32.lib

mbedtls_tls.lib
mbedtls_x509.lib
mbedtls_crypto_.lib
```

---

### Library Search Path

```
.\vendor\mbedTLS\lib
```

---

### Linker Flags

```
/nologo
/subsystem:windows
/incremental:no
/pdb:"Release\smtprealy98.pdb"
/machine:I386
/out:"Release\smtprealy98.exe"
/libpath:".\vendor\mbedTLS\lib"
```

---

### Output

```
Release\smtprealy98.exe
```

Verified on:

- Windows 98 SE
- Pentium III hardware
- Modern SMTP submission servers using STARTTLS + AUTH

---
