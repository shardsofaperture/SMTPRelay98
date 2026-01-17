

# SMTPRelay98 / TLSWrap98

SMTPRelay98 (also referred to as TLSWrap98) is a Windows 98–compatible local TLS
relay that allows legacy, non-TLS-aware applications to communicate with modern
TLS 1.2 servers.

It runs as a lightweight system-tray application and exposes local plaintext
TCP ports that are transparently bridged to remote TLS endpoints using an
in-process mbedTLS stack.

This project is designed to:
- Run on Windows 98 / 98 SE
- Compile with Visual C++ 6.0
- Operate on Pentium III–class hardware
- Avoid SChannel, OpenSSL, KernelEx, or system TLS dependencies

---

## How It Works

Legacy applications connect to local plaintext ports (e.g. 2525, 2993).
SMTPRelay98 establishes outbound TLS 1.2 connections to modern servers and
forwards data bidirectionally.

TLS is handled entirely inside the application.

---

## Features

- TLS 1.2 client support on Windows 98
- Multiple tunnels via INI configuration
- Direct TLS and SMTP STARTTLS modes
- System tray control (start/stop, config, logs)
- Fully in-process crypto (no external TLS libraries)
- Built-in TLS smoketest mode

---

## TLS Smoketest

A built-in smoketest validates TCP, DNS, RNG, SNI, and TLS 1.2 independently of
the tunnel system.

Run:


smtprealy98.exe -tls-test


This creates `tls_test.log` and performs a real TLS 1.2 handshake and HTTP
request against a modern server.

---

## Configuration

Runtime configuration is provided via `tlswrap98.ini`, which must reside next
to the executable. Tunnel sections must be named `tunnel <name>` and define a
local listen port and a remote TLS endpoint.

---

## License

All original SMTPRelay98 / TLSWrap98 source code is licensed under the **MIT
License**.

This project statically links against **mbedTLS**, which is licensed under the
**Apache License, Version 2.0**.

Accordingly:
- mbedTLS copyright and license notices are preserved
- Apache 2.0 terms apply to the mbedTLS portions
- MIT terms apply to all original project code

See:
- `LICENSE` (MIT)
- `vendor/mbedTLS/LICENSE` (Apache 2.0)
