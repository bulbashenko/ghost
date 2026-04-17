# GHOST Wire Protocol — v0 (draft)

This document defines the on-the-wire format of GHOST. It is the **source of truth** for all encoding/decoding code. If implementation diverges from this document, the document is wrong — fix it here first, then in code.

**Status:** v0 draft (Phase 0 bootstrap). Will be revised iteratively through Phases 1–4 and finalized in Phase 8.

**Protocol version byte:** `0x01` (see [internal/version/version.go](internal/version/version.go))

---

## Layered View

GHOST encapsulates tunnel traffic inside legitimate-looking HTTPS. From the network observer's perspective, only L1 and L2 are visible (and L2 only as opaque encrypted bytes). Layers L3–L5 live entirely inside the TLS record stream.

```
+--------------------------------------------------------------+
| L5  Traffic Shaper      (timing + padding, no wire bytes)    |
+--------------------------------------------------------------+
| L4  Multiplexer Frame   [Version|Type|StreamID|Length|Pld]   |
+--------------------------------------------------------------+
| L3  Session Cipher      ChaCha20-Poly1305 (Noise IK derived) |
+--------------------------------------------------------------+
| L2  HTTP/2 DATA frames  POST /api/v1/stream                  |
+--------------------------------------------------------------+
| L1  TLS 1.3 records     uTLS Chrome fingerprint, real cert   |
+--------------------------------------------------------------+
| TCP / IP                                                     |
+--------------------------------------------------------------+
```

Only **L4 frames** and the **L3 handshake message** are GHOST-defined wire formats. Everything below L4 is either standard (TLS, HTTP/2) or library-defined (Noise).

---

## L1 — Transport (TLS 1.3)

- **Cipher suites:** whatever the uTLS Chrome fingerprint negotiates. Server side runs standard `crypto/tls` and accepts modern Chrome ciphers.
- **Certificate:** real CA-signed (Let's Encrypt). No self-signed certs ever.
- **ALPN:** `h2` (HTTP/2). Required.
- **SNI:** server's real domain name.
- **Client fingerprint:** `utls.HelloChrome_Auto` — auto-tracks current stable Chrome.

No GHOST-specific bytes at this layer.

---

## L2 — HTTP/2 Camouflage

The client sends a single HTTP/2 request:

```
:method   POST
:scheme   https
:path     /api/v1/stream
:authority server.example.com
content-type        application/octet-stream
user-agent          <realistic Chrome UA matching utls fingerprint>
accept              */*
accept-encoding     gzip, deflate, br
accept-language     en-US,en;q=0.9
```

Request body = the **L3 handshake envelope** (see below).

Server response:

- **Auth success** → `200 OK` with `content-type: application/octet-stream`. Response body begins with the Noise IK responder message; subsequent HTTP/2 DATA frames carry **L4 multiplexer frames** in both directions.
- **Auth failure** → server transparently reverse-proxies the request to the configured `fallback_target`. Response is byte-identical to what the fallback would have returned. No tell.

The path `/api/v1/stream` is the only "magic" string. All other paths route to fallback.

---

## L3 — Authentication Envelope

The L3 envelope wraps the Noise IK handshake message and pads it to a length sampled from the cover-traffic distribution.

```
+-----------------+--------------------+----------------------+
| NoiseLen (2 BE) | NoiseMsg (NoiseLen)| Padding (random N)   |
+-----------------+--------------------+----------------------+
```

| Field      | Size       | Description                                                            |
|------------|------------|------------------------------------------------------------------------|
| `NoiseLen` | 2 bytes BE | Length of `NoiseMsg` in bytes. Max 4096.                               |
| `NoiseMsg` | variable   | Noise IK initiator message (`-> e, es, s, ss`). Includes ephemeral pub, encrypted static pub, and any 0-RTT payload. |
| `Padding`  | variable   | Cryptographically random bytes. Length sampled from L5 distribution to match real API request body sizes. Discarded by server. |

**Noise pattern:** `Noise_IK_25519_ChaChaPoly_BLAKE2s`

After the handshake completes:

- Both sides derive two cipher states (send + recv) keyed with ChaCha20-Poly1305.
- Each L4 frame payload is encrypted under the appropriate cipher state.
- Each direction maintains a 64-element sliding replay window (nonces are sequential per cipher state, but the window guards against reordering attacks at the HTTP/2 layer).

**Constant-time discipline:** All comparisons (MACs, key prefixes, version checks) MUST use `crypto/subtle`. On any auth failure, the server falls through to the reverse-proxy path **without an early return** — execution time of valid vs invalid auth must be statistically indistinguishable.

---

## L4 — Multiplexer Frame

After L3 handshake, all subsequent payload bytes (in both directions) are framed as:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1B) |   Type (1B)   |        StreamID (4 B)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                              |
|                                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Length (2 B)          |        Payload (Length B)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                              |
|                          ...                                 |
+--------------------------------------------------------------+
```

| Field      | Size       | Description                                                       |
|------------|------------|-------------------------------------------------------------------|
| `Version`  | 1 byte     | Protocol version. Currently `0x01`.                               |
| `Type`     | 1 byte     | Frame type (see table).                                           |
| `StreamID` | 4 bytes BE | Logical stream identifier. Client-initiated odd, server even.     |
| `Length`   | 2 bytes BE | Length of `Payload` in bytes. Max 65535.                          |
| `Payload`  | variable   | Encrypted with L3 session cipher. May be zero-length.             |

### Frame types

| Code   | Name            | Direction | Payload                                          |
|--------|-----------------|-----------|--------------------------------------------------|
| `0x00` | `DATA`          | both      | Stream payload bytes (after L3 decrypt)          |
| `0x01` | `WINDOW_UPDATE` | both      | uint32 BE: credit increment in bytes             |
| `0x02` | `STREAM_OPEN`   | both      | Empty (StreamID is the new stream)               |
| `0x03` | `STREAM_CLOSE`  | both      | Empty                                            |
| `0x04` | `PING`          | both      | 8-byte opaque echo cookie                        |
| `0x05` | `PADDING`       | both      | Random bytes; receiver MUST decrypt and discard  |
| `0x06` | `MIGRATE`       | reserved  | Stream migration (v2, not implemented in v1)     |

`StreamID = 0` is reserved for connection-level frames (`PING`, `PADDING`, `WINDOW_UPDATE` against the connection itself).

### Flow control

Credit-based, simple. Each side starts with a per-stream window of `65536` bytes. Receiver sends `WINDOW_UPDATE` to grant additional credit. Sender MUST NOT exceed available credit.

### Keepalive

Either side MAY send `PING` frames. Recipient MUST respond with a matching `PING` (same cookie). Default interval: 30 s. Three missed PINGs → close connection.

---

## L5 — Traffic Shaper (no wire bytes)

L5 has no on-the-wire format of its own. It influences:

1. **When** L4 frames are emitted (burst timing, IAT distribution)
2. **What padding** is injected (extra `PADDING` frames to enforce asymmetric byte ratio)
3. **Connection lifetime** (rotation cadence)

All L5 decisions are local to each side. They are observable only as flow statistics, which is exactly the point — they're tuned to match a real HTTPS distribution captured from cover traffic.

See [research/06-proposed-architecture.md](../research/06-proposed-architecture.md) §L5 for design details.

---

## Endianness

All multi-byte integer fields are **big-endian** (network byte order).

## Security Notes

- **No metadata in plaintext.** Frame headers (Version/Type/StreamID/Length) ARE plaintext within the TLS stream — they're encrypted by TLS but visible to the L3 cipher boundary. They contain no sensitive information.
- **Replay protection** lives at L3 (Noise nonce sequence + sliding window). L4 has no replay defense of its own.
- **Padding is not authenticated separately.** It's encrypted as a normal frame payload, so tampering is caught by Poly1305.
- **Length oracles.** L2 and L4 lengths are visible to TLS-aware observers as TLS record sizes, but L5 padding ensures distributions match cover traffic.

---

## Open Items (resolved during Phases 1–4)

- [ ] Exact Noise IK message size after Phase 1 implementation
- [ ] Padding length distribution (Phase 6 calibration)
- [ ] Whether `STREAM_OPEN` needs an initial-data field
- [ ] Server response headers list (Phase 3)
- [ ] Whether HTTP/2 server PUSH is used (probably not)

## Change Log

- **v0** (Phase 0, 2026-04-10): Initial draft based on `research/06-proposed-architecture.md`.
