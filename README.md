# Threema OnPrem Node.js Server

A self-hosted, protocol-compatible **Threema OnPrem** backend written in **Node.js, TypeScript, and Prisma (PostgreSQL)**.

It implements the complete wire protocol required by official **Threema OnPrem Android (6.6.0+)** and **Threema Desktop 2.0 (`libthreema` / Multi-Device)** clients—including signed OPPF discovery, Work license and directory sync, end-to-end encrypted Chat Server Protocol (CSP v2), Device-to-Mediator (D2M) multi-device synchronization, Rendezvous WebSocket relay, encrypted media blobs, Threema Safe backups, an embedded RFC 5389/5766 STUN/TURN UDP VoIP relay, and an **IBM Carbon v11 Admin Console**.

---

## Table of Contents

1. [Architecture & Protocol Subsystems](#1-architecture--protocol-subsystems)
2. [Project Structure](#2-project-structure)
3. [Prerequisites](#3-prerequisites)
4. [Quick Start (Local Deployment)](#4-quick-start-local-deployment)
5. [Production Deployment from Scratch](#5-production-deployment-from-scratch)
   - [5.1 DNS & Split-Hostname Architecture (Cloudflare Tunnel + Direct TCP/UDP)](#51-dns--split-hostname-architecture-cloudflare-tunnel--direct-tcpudp)
   - [5.2 Firewall & Port Forwarding Rules](#52-firewall--port-forwarding-rules)
   - [5.3 Production `.env` Configuration](#53-production-env-configuration)
   - [5.4 Running as a Persistent Service (`systemd` / PM2)](#54-running-as-a-persistent-service-systemd--pm2)
6. [Onboarding Clients (Android & Desktop 2.0)](#6-onboarding-clients-android--desktop-20)
7. [Admin Web Console & REST API](#7-admin-web-console--rest-api)
8. [Environment Variables Reference](#8-environment-variables-reference)
9. [Testing & Verification](#9-testing--verification)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Architecture & Protocol Subsystems

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Threema OnPrem Clients                               │
│     • Threema OnPrem Android (6.6.0+)     • Threema Desktop 2.0 (Electron)   │
└───────────────┬───────────────────────────────────┬──────────────────────────┘
                │                                   │
   HTTPS / WSS (Port 8443 / 443)       Raw TCP (Port 5222) & UDP (3478, 49152+)
   (Can be routed via Reverse Proxy    (Must connect directly / NAT-forwarded;
    or Cloudflare Tunnel)               HTTP proxies do not carry raw CSP/UDP)
                │                                   │
                ▼                                   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     Threema OnPrem Node.js Server                            │
│                                                                              │
│  ┌────────────────────────────────────┐  ┌────────────────────────────────┐  │
│  │ HTTP / REST Services               │  │ Real-Time & Transport Services │  │
│  │ • /config.oppf (Ed25519 JWS)       │  │ • CSP v2 TCP Server (:5222)    │  │
│  │ • /directory/* (ID, contacts, VEP) │  │ • D2M Mediator WS (/mediator)  │  │
│  │ • /work/* (License, MDM, wdir)     │  │   └─ CSP over D2M Proxy        │  │
│  │ • /blobs/* (Sharded disk storage)  │  │ • Rendezvous WS (/rendezvous)  │  │
│  │ • /safe/* (Encrypted backups)      │  │ • STUN/TURN UDP Relay (:3478)  │  │
│  │ • /avatar/* (Profile avatars)      │  │ • Housekeeping TTL Sweeper     │  │
│  │ • /admin/ui (IBM Carbon v11 UI)    │  │                                │  │
│  └────────────────────────────────────┘  └────────────────────────────────┘  │
│                                       │                                      │
│                                       ▼                                      │
│             ┌──────────────────────────────────────────────────┐             │
│             │  SQLite (WAL Mode) + Sharded Disk Blob Storage   │             │
│             │  • prisma/dev.db           • data/blobs/<aa>/<id>│             │
│             └──────────────────────────────────────────────────┘             │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Key Subsystems Implemented

| Subsystem | Endpoints / Ports | Description |
| :--- | :--- | :--- |
| **OPPF Provisioning** | `GET /config.oppf`, `GET /prov/config.oppf`, `GET /config.fallback.oppf` | Dynamically signs the OnPrem Provisioning File (JWS Compact Serialization, `alg: "EdDSA"`, Ed25519) with server URLs, CSP public keys, TURN servers, and feature flags. |
| **Directory Service** | `/directory/*` | Identity creation (`NaCl Box` voucher & challenge-response), public key lookups, contact matching (`match_token` & `match`), private key data auth (`fetch_priv`), feature masks, revocation (`revoke`, `ws/revoke`), blob & VoIPTURN credentials (`blob_cred`, `voip_cred`), and spam reports. |
| **Work & MDM Service** | `/work/*` | License check (`check_license`), organization directory & MDM settings (`fetch2`), company contact directory search (`directory`), self-hosted org logos (`/work/logo/light`, `/work/logo/dark`), `libthreema` protobuf user properties (`/work/api-client/v1/user-properties`), and Remote Secret lockout (`/work/api-client/v1/remote-secret`). |
| **Chat Server Protocol (CSP v2)** | TCP `:5222` & D2M Proxy | Curve25519 + XSalsa20-Poly1305 handshake, login validation, offline message queue, immediate delivery & acks, payload v0/v1/v3 conversion, push token registration (`0x20`/`0x24`/`0x25`), device cookie indications (`0xd2`/`0xd3`), and server alerts (`0xe1`). |
| **D2M Multi-Device Mediator** | `WSS /mediator/:path` | Binary Device-to-Mediator protocol (`libthreema` `md-d2m`), leader election, device slot management, atomic reflection transactions (`BEGIN_TRANSACTION`/`COMMIT_TRANSACTION`), persistent reflection queue, and embedded CSP proxy containers for Desktop 2.0. |
| **Rendezvous Relay** | `WSS /rendezvous/:channel` | Ephemeral 1:1 binary WebSocket pairing channel used during QR-code device linking between mobile and Desktop 2.0. |
| **Media Blob Server** | `POST /blobs`, `GET /blobs/:id`, `DELETE /blobs/:id` | Sharded disk-backed encrypted blob storage (`data/blobs/<prefix>/<blobId>`) with legacy database fallback and automatic TTL cleanup. |
| **Threema Safe & Avatars** | `/safe/*`, `/avatar/*` | Encrypted identity backup storage (`GET /safe/config`, `PUT/GET/DELETE /safe/backups/:id`) and ETag-cached avatar distribution. |
| **STUN / TURN VoIP Relay** | UDP `:3478` + `:49152-49252` | Built-in RFC 5389 / RFC 5766 STUN & TURN UDP server with HMAC-SHA1 time-limited credentials (`/directory/identity/voip_cred`) and periodic DNS external IP refresh for 1:1 encrypted voice/video calls. |
| **Admin Console & API** | `GET /admin/ui`, `/admin/*` | Self-hosted **IBM Carbon Design System v11** (G100 Dark / G10 Light) dashboard and REST API for managing identities, Work accounts, MDM policies, logos, live sessions, D2M device groups, remote secrets, and storage maintenance. |

---

## 2. Project Structure

```text
onprem-server/
├── docker-compose.yml           # Optional Docker Compose stack for PostgreSQL
├── prisma/
│   └── schema.prisma            # PostgreSQL schema (Identities, WorkAccounts, QueuedMessages, D2M, Blobs, Safe, MDM)
├── src/
│   ├── index.ts                 # Main server entrypoint & graceful shutdown orchestrator
│   ├── config.ts                # Environment variable loader & typed ServerConfig
│   ├── db.ts                    # Prisma client factory, database connection health check, & default seeder
│   ├── logger.ts                # Structured logger
│   ├── auth/
│   │   └── workAuth.ts          # Work license credential verification
│   ├── cli/
│   │   ├── initKeys.ts          # CLI utility to initialize/display Ed25519 & Curve25519 server keys
│   │   ├── initTls.ts           # CLI utility to generate local CA + SAN TLS certificates
│   │   └── migrateSqliteToPg.ts # One-command migration tool from legacy SQLite (dev.db) to PostgreSQL
│   ├── crypto/
│   │   ├── keyManager.ts        # Persistent OPPF Ed25519 & CSP Curve25519 key management
│   │   ├── primitives.ts        # NaCl Box, XSalsa20-Poly1305, HSalsa20, Ed25519, JWS helpers
│   │   └── tlsCert.ts           # X.509 CA & leaf certificate generator with SPKI SHA-256 computation
│   ├── csp/
│   │   ├── protocol.ts          # CSP packet framing, payload v0/v1/v3 conversion, handshake parsers
│   │   ├── server.ts            # Raw TCP listener on port 5222
│   │   └── session.ts           # CspSession state machine & CspRouter message delivery engine
│   ├── d2m/
│   │   ├── proto.ts             # Binary D2M framing, close codes (md-d2m.struct.yml), & packet encoders
│   │   └── mediator.ts          # D2M WebSocket mediator, reflection queue, & D2M->CSP virtual transport
│   ├── maintenance/
│   │   └── sweeper.ts           # Periodic TTL garbage collector (tokens, messages, blobs, D2M, Safe)
│   ├── middleware/
│   │   └── rateLimit.ts         # Sliding-window HTTP rate limiter
│   ├── rendezvous/
│   │   └── server.ts            # Rendezvous WebSocket pairing relay for Desktop 2.0 QR linking
│   ├── routes/
│   │   ├── admin.ts             # /admin/* REST API (X-Admin-Key protected)
│   │   ├── adminUi.ts           # /admin/ui IBM Carbon v11 single-page dashboard
│   │   ├── avatar.ts            # /avatar/* profile picture endpoints
│   │   ├── blob.ts              # /blobs/* encrypted file/media upload & download
│   │   ├── directory.ts         # /directory/* router aggregator
│   │   ├── directory/           # Modular directory handlers (identity, matching, credentials, reports, shared)
│   │   ├── oppf.ts              # /config.oppf JWS generator
│   │   ├── safe.ts              # /safe/* Threema Safe backup endpoints
│   │   └── work.ts              # /work/* Work directory, MDM, logos, user-properties, & remote-secret
│   └── turn/
│       └── server.ts            # Embedded STUN/TURN UDP relay server for voice & video calls
└── test/                        # Modular integration test suites (8 suites, 16 end-to-end tests)
```

---

## 3. Prerequisites

- **Node.js**: `v20.12+` or `v22+` / `v24+` (ESM + native `crypto` support required)
- **PostgreSQL**: `v15+` (native PostgreSQL 16/17/18 service or via the included `docker-compose.yml`)
- **npm**: `v10+`
- **OS**: Linux, Windows, or macOS
- **Network**:
  - HTTPS/WSS termination for the HTTP port (`8443` or via reverse proxy/Cloudflare Tunnel on `443`)
  - Direct TCP reachability on **`5222`** (CSP chat protocol)
  - Direct UDP reachability on **`3478`** and **`49152-49252`** (STUN/TURN voice & video call relay)

---

## 4. Quick Start (Local Deployment)

Follow these steps to set up and run the server locally from scratch:

### Step 1: Install Dependencies

```bash
cd onprem-server
npm install
```

### Step 2: Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

*(On Windows PowerShell: `Copy-Item .env.example .env`)*

### Step 3: Initialize the PostgreSQL Database

Ensure PostgreSQL is running (either via a native PostgreSQL service on port `5432` or via `docker compose up -d`) and that `DATABASE_URL` in `.env` points to your database (e.g., `postgresql://postgres:<password>@localhost:5432/threema_onprem?schema=public`).

Generate the Prisma client and push the schema to PostgreSQL:

```bash
npm run db:generate
npm run db:push
```

*(Optional) If you are migrating existing data from a legacy `prisma/dev.db` SQLite database:*
```bash
npm run db:migrate:sqlite
```

### Step 4: Initialize Cryptographic Server Keys

Generate (or inspect existing) persistent server keys (`oppf_ed25519` and `csp_curve25519`) and seed the default Work account:

```bash
npm run keys:init
```

Example output:
```text
Initialized server keys and default account:
  OPPF Ed25519 Public Key (Base64): gFYqhjw0fCWEVtTHXfgcmIz3ez4zISlRYvblgz/svds=
  CSP Curve25519 Public Key (Base64): 6ofyP2NLh0QZWpAJiKMweHuL2M0ZgeLvP4WIxAZZkk8=
  Default Work Username: demo
```

> **Important:** Save the **OPPF Ed25519 Public Key (Base64)**! You will need this key together with your OPPF URL (`https://<your-domain>/config.oppf`) to provision the Threema OnPrem app.

### Step 5: (Optional) Generate Local TLS Certificates

If you are running directly without an external TLS reverse proxy and want local HTTPS (`TLS_ENABLED="true"`):

```bash
npm run tls:init
```

This creates a local CA and SAN certificate bundle under `./certs/`.

### Step 6: Start the Server

For development with hot-reload:
```bash
npm run dev
```

For production build and execution:
```bash
npm run build
npm start
```

Once running, open the **IBM Carbon v11 Admin Console** at:
- `http://localhost:8443/admin/ui` (or `https://<your-domain>/admin/ui`)
- Log in with the `ADMIN_API_KEY` from your `.env` file.

---

## 5. Production Deployment from Scratch

### 5.1 DNS & Split-Hostname Architecture (Cloudflare Tunnel + Direct TCP/UDP)

Threema OnPrem uses **two distinct types of network traffic**:

1. **HTTP/HTTPS & WebSockets (`/config.oppf`, `/directory/*`, `/work/*`, `/blobs/*`, `/safe/*`, `/rendezvous/*`, `/mediator/*`)**:
   - Standard HTTPS & WSS traffic.
   - Can be routed through a **Cloudflare Tunnel (`cloudflared`)** or standard reverse proxy (Nginx / Caddy / Traefik) on port `443`.
2. **Raw Binary TCP (`5222` for CSP) & UDP (`3478` + `49152-49252` for TURN VoIP Calls)**:
   - Cannot pass through standard HTTP-only Cloudflare Tunnels or orange-cloud HTTP proxies.
   - Must resolve directly to your server's public IP address via a **DNS-only ("Grey Cloud") `A` record** (or DDNS hostname) with NAT/firewall port forwarding.

#### Recommended DNS Layout (Example Domain: `thr.example.com`)

| Record Type | Hostname | Target / Value | Proxy Status | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `CNAME` / `A` | `thr.example.com` | Cloudflare Tunnel or Reverse Proxy | Proxied (Orange Cloud) or Direct TLS | HTTPS APIs, OPPF, Blobs, Safe, D2M & Rendezvous WebSockets, Admin UI |
| `A` | `chat.thr.example.com` | `<Your Public WAN IPv4>` | **DNS Only (Grey Cloud)** | Raw TCP `:5222` (CSP Chat) & UDP `:3478` + `:49152-49252` (TURN VoIP) |

### 5.2 Firewall & Port Forwarding Rules

On your router / cloud firewall, forward the following ports to the host running `onprem-server`:

| Protocol | External Port(s) | Internal Port(s) | Required By |
| :--- | :--- | :--- | :--- |
| **TCP** | `443` (or via CF Tunnel -> `8443`) | `8443` | HTTPS REST APIs, OPPF, WebSockets (`/rendezvous`, `/mediator`), Admin UI |
| **TCP** | `5222` | `5222` | Chat Server Protocol (CSP v2) for Android & iOS clients |
| **UDP** | `3478` | `3478` | STUN / TURN control port for voice & video calls |
| **UDP** | `49152 - 49252` | `49152 - 49252` | TURN media relay allocation ports for voice & video calls |

### 5.3 Production `.env` Configuration

Below is a complete production `.env` template using the split-hostname setup (`thr.example.com` for HTTP/WS and `chat.thr.example.com` for CSP TCP & TURN UDP):

```dotenv
# Database & Storage
DATABASE_URL="postgresql://postgres:your-password@localhost:5432/threema_onprem?schema=public"
BLOB_STORAGE_DIR="./data/blobs"
BLOB_TTL_HOURS="336"
HOUSEKEEPING_INTERVAL_MINUTES="10"

# Bind Addresses
HOST="0.0.0.0"
HTTP_PORT="8443"
CSP_PORT="5222"

# Public Origins advertised inside /config.oppf
PUBLIC_HTTP_ORIGIN="https://thr.example.com"
PUBLIC_WS_ORIGIN="wss://thr.example.com"
PUBLIC_ORIGIN_STATIC="true"

# Direct DNS-only hostname for TCP 5222 (CSP)
CSP_HOST="chat.thr.example.com"
CSP_PUBLIC_PORTS="5222"

# TLS (Set TLS_ENABLED="false" if Cloudflare Tunnel / Nginx terminates TLS in front of port 8443)
TLS_ENABLED="false"
TLS_CERT_PATH=""
TLS_KEY_PATH=""
TLS_PIN_SPKI="false"

# Organization & Default Work Account
LICENSE_ID="onprem-prod-001"
LICENSE_EXPIRES="2030-12-31"
LICENSE_COUNT="250"
ORG_NAME="Acme OnPrem"
SUPPORT_TEXT="support@example.com"
DEFAULT_WORK_USERNAME="demo"
DEFAULT_WORK_PASSWORD="change-me-immediately"

# Admin Web Console & API Key (Required for /admin/ui and /admin/*)
ADMIN_API_KEY="replace-with-a-long-random-secret-key"

# Built-in STUN/TURN VoIP Relay Server
TURN_ENABLED="true"
TURN_HOST="chat.thr.example.com"
# Optional: Leave TURN_EXTERNAL_IP blank to auto-resolve TURN_HOST via DNS every 5 minutes,
# or set explicitly to your public WAN IPv4 address.
TURN_EXTERNAL_IP=""
TURN_PORT="3478"
TURN_MIN_PORT="49152"
TURN_MAX_PORT="49252"
TURN_SECRET="replace-with-a-random-turn-hmac-secret"

# Security & Rate Limiting
CORS_ALLOWED_ORIGINS=""
RATE_LIMIT_ENABLED="true"
RATE_LIMIT_WINDOW_MS="60000"
RATE_LIMIT_MAX_REQUESTS="240"
REMOTE_SECRET_ENABLED="false"
LOG_LEVEL="info"
```

> **Note on Cryptographic Keys (`ServerKey` table in PostgreSQL)**:
> On first boot (or when running `npm run keys:init`), the server generates its `oppf_ed25519` and `csp_curve25519` keypairs and stores them in the `ServerKey` table in PostgreSQL. **Back up your PostgreSQL database (`pg_dump threema_onprem`) regularly**—enrolled clients pin both the OPPF Ed25519 public key and CSP Curve25519 public key.

### 5.4 Running as a Persistent Service (`systemd` / PM2)

#### Option A: `systemd` (Linux)

```ini
# /etc/systemd/system/threema-onprem.service
[Unit]
Description=Threema OnPrem Node.js Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/threema-onprem/onprem-server
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now threema-onprem
```

#### Option B: PM2 (Windows / Linux / macOS)

```bash
npm run build
pm2 start dist/index.js --name threema-onprem
pm2 save
```

---

## 6. Onboarding Clients (Android & Desktop 2.0)

### 6.1 Provisioning Threema OnPrem Android

1. Retrieve your **OPPF URL** and **OPPF Ed25519 Public Key** from the startup console output or from the **Overview** tab of `/admin/ui`:
   - **OPPF URL**: `https://thr.example.com/config.oppf`
   - **OPPF Public Key**: `<Base64 Ed25519 Public Key, e.g. gFYqhjw0fCWEVtTHXfgcmIz3ez4zISlRYvblgz/svds=>`
2. Configure the Threema OnPrem Android app via Managed App Configuration (MDM) or QR / provisioning profile with:
   - Configuration URL: `https://thr.example.com/config.oppf`
   - Public Key: `<OPPF Ed25519 Public Key>`
3. Launch the Android app and enter a valid **Work License Account** username and password (create accounts in `/admin/ui` under **Work License Accounts**, or use the default account seeded from `DEFAULT_WORK_USERNAME` / `DEFAULT_WORK_PASSWORD`).
4. Complete identity generation. Your user will automatically appear in `/admin/ui` under **Directory Identities** and synchronize with other users in your organization's Work Directory.

### 6.2 Linking Threema Desktop 2.0 (Multi-Device)

1. On the enrolled Android device, enable Multi-Device / Link New Device.
2. Open **Threema Desktop 2.0** (configured for your OnPrem OPPF URL & public key).
3. Scan the Desktop QR code with the Android app:
   - Both peers pair over `WSS /rendezvous/:channel`.
   - Desktop authenticates against `/directory/identity/fetch_priv` (full CORS support for `threemadesktop://app` is built in).
   - Both devices synchronize end-to-end encrypted state over the D2M Mediator (`WSS /mediator/:path`) and proxy CSP messages seamlessly.

---

## 7. Admin Web Console & REST API

The server includes a self-hosted **IBM Carbon Design System v11** administration dashboard:

- **Web Console URL**: `https://<your-domain>/admin/ui`
- **Authentication**: Enter your `ADMIN_API_KEY` (sent as `X-Admin-Key` header on all `/admin/*` requests).
- **Theme Support**: Toggle between **Carbon G100 (Dark)** and **Carbon G10 (Light)** from the top shell bar.

### Admin Capabilities

| Section | Features |
| :--- | :--- |
| **Overview & Live Sessions** | Real-time KPIs (active CSP sessions, D2M mediator connections/groups/transactions, identity counts, TURN relay allocations, blob & Safe storage, uptime), OPPF & CSP public key inspection, live CSP session table, and **Broadcast CSP Server Alert (`0xe1`)**. |
| **Directory Identities** | Search/filter registered Threema IDs, inspect online badges, edit public nicknames and Work profile fields (first/last name, job title, department, category, CSI, Work Directory visibility), revoke identities (immediately disconnects active CSP sessions), or delete identities. |
| **Work License Accounts** | Create new Work license credentials with template profile attributes, enable/disable accounts, reset passwords, and inspect linked Threema IDs. |
| **Organization & MDM** | Edit organization name, support contact, check interval, Work directory categories JSON, Threema MDM policy parameters JSON, toggle Remote Secret support, and upload/delete self-hosted light & dark logos (`/work/logo/light`, `/work/logo/dark`). |
| **D2M Devices & Secrets** | Inspect multi-device groups (`dgid`), connected device slots, leader status, and reflection counters; force-drop compromised device slots; block/unblock or delete Remote Secrets. |
| **Reports & Maintenance** | Trigger on-demand TTL housekeeping garbage collection (`POST /admin/cleanup`) and review/dismiss user-submitted spam or abuse reports. |

---

## 8. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql://postgres:postgres@localhost:5432/threema_onprem?schema=public` | Prisma PostgreSQL connection string. |
| `HOST` | `0.0.0.0` | Interface bind address for HTTP, CSP TCP, and TURN UDP listeners. |
| `HTTP_PORT` | `8443` | Local TCP port for HTTP/HTTPS & WebSocket server. |
| `CSP_PORT` | `5222` | Local TCP port for the binary Chat Server Protocol (CSP v2) listener. |
| `PUBLIC_HTTP_ORIGIN` | `http(s)://localhost:8443` | Public HTTP(S) base URL embedded into signed `/config.oppf` descriptors. |
| `PUBLIC_WS_ORIGIN` | `ws(s)://localhost:8443` | Public WS(S) base URL embedded into `/config.oppf` for `/rendezvous` and `/mediator`. |
| `PUBLIC_ORIGIN_STATIC` | `false` | When `true`, always uses `PUBLIC_HTTP_ORIGIN`/`PUBLIC_WS_ORIGIN` instead of inferring from the request `Host` header. Set to `true` in production. |
| `CSP_HOST` | `localhost` | Public hostname or IP advertised in `/config.oppf` for raw TCP CSP connections. |
| `CSP_PUBLIC_PORTS` | *(defaults to `CSP_PORT`)* | Comma-separated public TCP ports advertised in `/config.oppf` for CSP. |
| `TLS_ENABLED` | `false` | Enable native HTTPS/WSS using `TLS_CERT_PATH` and `TLS_KEY_PATH`. Leave `false` when behind a TLS-terminating tunnel or reverse proxy. |
| `TLS_CERT_PATH` | `""` | Path to PEM server certificate / fullchain when `TLS_ENABLED="true"`. |
| `TLS_KEY_PATH` | `""` | Path to PEM private key when `TLS_ENABLED="true"`. |
| `TLS_PIN_SPKI` | `false` | Embed the leaf certificate's SPKI SHA-256 hash in `/config.oppf` (`pinnedCertificates`). |
| `ADMIN_API_KEY` | `dev-admin-key` | Secret key required by `/admin/ui` and all `/admin/*` endpoints (`X-Admin-Key`). |
| `ORG_NAME` | `OnPrem Organization` | Initial organization name seeded into `WorkMdmConfig`. |
| `SUPPORT_TEXT` | `support@onprem.local` | Support contact string returned by `/work/fetch2`. |
| `DEFAULT_WORK_USERNAME` | `demo` | Default Work license username seeded on initial startup. |
| `DEFAULT_WORK_PASSWORD` | `demo-password` | Default Work license password seeded on initial startup. |
| `TURN_ENABLED` | `true` | Enable the embedded RFC 5389/5766 STUN/TURN UDP relay server. |
| `TURN_HOST` | *(defaults to `CSP_HOST`)* | Public hostname advertised for TURN in `/config.oppf`. |
| `TURN_EXTERNAL_IP` | `""` | Public IPv4 address placed in TURN `XOR-RELAYED-ADDRESS`. Auto-resolved from `TURN_HOST` every 5 minutes if left blank. |
| `TURN_PORT` | `3478` | UDP port for STUN/TURN control traffic. |
| `TURN_MIN_PORT` / `TURN_MAX_PORT` | `49152` / `49252` | UDP port range used for TURN media relay allocations. |
| `BLOB_STORAGE_DIR` | `./data/blobs` | Directory for sharded encrypted media blob files. |
| `BLOB_TTL_HOURS` | `336` (14 days) | Retention period before uploaded blobs expire and are purged by the sweeper. |
| `HOUSEKEEPING_INTERVAL_MINUTES` | `10` | Interval in minutes between automatic background TTL cleanup runs. |
| `RATE_LIMIT_ENABLED` | `true` | Enable sliding-window HTTP rate limiting (`429 Too Many Requests`). |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window duration in milliseconds. |
| `RATE_LIMIT_MAX_REQUESTS` | `240` | Maximum requests per IP within `RATE_LIMIT_WINDOW_MS`. |
| `REMOTE_SECRET_ENABLED` | `false` | Default value for the OPPF `features.remoteSecret` flag on fresh databases. |

---

## 9. Testing & Verification

The project ships with 8 modular end-to-end integration test suites (`test/*.test.ts`) covering every protocol surface:

- `test/oppf.test.ts` — JWS Ed25519 signature verification & OPPF payload structure
- `test/directory.test.ts` — Identity creation, challenge-response, bulk fetch, contact matching, revocation
- `test/work.test.ts` — Work license check, `fetch2`, wildcard directory search, logos, protobuf `user-properties`, `remote-secret`
- `test/blob-safe-avatar.test.ts` — Sharded disk blob upload/download/deletion, Threema Safe backups, ETag avatars
- `test/csp.test.ts` — Raw TCP CSP handshake, bidirectional E2E message routing, payload v0/v1/v3 conversion, push tokens, device cookie indications, server alerts
- `test/d2m.test.ts` — Rendezvous QR pairing, D2M leader election, reflection transactions, D2M-proxied CSP sessions
- `test/turn.test.ts` — TURN credentials, STUN binding, authenticated TURN UDP allocation & permission flow
- `test/admin-resiliency.test.ts` — Admin UI/API CRUD, constant-time auth, TTL housekeeping sweeper, sliding-window rate limiting

Run the full test suite and TypeScript build check:

```bash
npm run build
npm test
```

---

## 10. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **Android can create an identity, but messages hang in "Sending" and users show as offline** | `CSP_HOST` points to a Cloudflare HTTP-proxied hostname that drops raw TCP port `5222`. | Create a DNS-only (`A` record, grey cloud) subdomain such as `chat.thr.example.com`, forward TCP port `5222` on your router/firewall, and set `CSP_HOST="chat.thr.example.com"` and `PUBLIC_ORIGIN_STATIC="true"`. |
| **Desktop 2.0 QR linking fails with CORS error on `/directory/identity/fetch_priv`** | Reverse proxy stripping or overriding CORS headers for `Origin: threemadesktop://app`. | Ensure your reverse proxy passes `OPTIONS` preflight requests directly to the Node.js server (which automatically echoes `Access-Control-Allow-Origin` for `threemadesktop://app`) and leave `CORS_ALLOWED_ORIGINS=""` (or include `threemadesktop://app`). |
| **Voice / video calls ring forever or fail to connect media** | UDP port `3478` or the relay port range `49152-49252` is blocked by NAT/firewall, or `TURN_HOST` resolves to a proxy IP. | Ensure `TURN_HOST` points to your direct WAN hostname (`chat.thr.example.com`) and forward UDP `3478` and UDP `49152-49252` to the server. |
| **Contacts show default placeholder names instead of real organization names** | Work Directory profile fields (`firstName`, `lastName`) or `publicNickname` haven't been populated. | Clients automatically sync their nickname via `POST /directory/identity/update_work_info` and `/work/api-client/v1/user-properties`, or you can edit any user's name, job title, and department directly in `/admin/ui` under **Directory Identities**. |
