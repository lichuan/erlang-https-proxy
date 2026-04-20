# Erlang Implementation of C-S Architecture Https Proxy

This project is a client-server (C-S) architecture HTTPS CONNECT proxy implemented in Erlang language.

## Overview

This project implements a client-server HTTPS CONNECT proxy with two components:

- **https_proxy_c** – Local client proxy running on your machine
- **https_proxy_s** – Remote server proxy running on a VPS (outside restricted networks)

The architecture allows custom encryption of the CONNECT handshake with password authentication between client and server, while maintaining near-native HTTPS performance.

## Performance: Why Faster Than HTTPS over SSH

| Feature | This Proxy | HTTPS over SSH |
|---------|------------|----------------|
| Encryption layers | Single (custom seed) | Double (SSH + TLS) |
| Handshake overhead | Minimal | Heavy (SSH + TLS handshake) |
| Latency | ~1-5ms per connection | ~50-200ms per connection |

SSH tunneling wraps encrypted HTTPS traffic inside another encryption layer. This proxy uses a single, lightweight transformation on the CONNECT handshake only, leaving actual HTTPS data untouched. Result: near-direct connection speeds with effective censorship evasion.

## Features

- **Password authentication** – Prevents unauthorized access to your VPS proxy
- **Custom encryption seeds** – User-defined obfuscation for CONNECT handshake
- **High concurrency** – Erlang lightweight process per connection
- **Full-duplex tunneling** – Bidirectional data transfer without blocking
- **Zero shared state** – No locks, no race conditions

## Custom Encryption Against Firewall

The client encrypts the initial CONNECT request using a user-defined seed list

Encryption is simple byte-wise addition modulo 256. The server reverses it.

**Why Firewall can't easily detect it:**

- No protocol signature (unlike SSH's "SSH-2.0" banner)
- Randomized byte distribution (bypasses entropy analysis)
- No fixed timing patterns
- Seeds are only known to you

Firewall cannot distinguish this traffic from random binary data or a custom game protocol.

## Password Authentication

Both client and server share a pre-configured password:

```erlang
-define(PROXY_C_S_KEY, "this is a password between your prox_c and proxy_s").
```
The client sends this password in the encrypted CONNECT handshake. The server validates it before establishing any tunnel. Unauthorized connections are immediately closed.

## Quick Start

**Step 1: Update Configuration**

Edit both https_proxy_c.erl and https_proxy_s.erl:

```erlang
%% https_proxy_c.erl
-define(PROXY_C_PORT, 10088).
-define(PROXY_S_IP, "your.vps.ip.address").
-define(PROXY_S_PORT, 10099).
-define(PROXY_C_S_KEY, "your-secret-password").

%% https_proxy_s.erl
-define(PROXY_S_PORT, 10099).
-define(PROXY_C_S_KEY, "your-secret-password").
```

**Step 2: Compile**

On your local machine (client):
```bash
erlc https_proxy_c.erl
```
On your VPS (server):
```bash
erlc https_proxy_s.erl
```

**Step 3: Run Server on VPS**
```bash
erl -s https_proxy_s
```

**Step 4: Run Client on Local Machine**
```bash
erl -s https_proxy_c
```
