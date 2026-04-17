# GHOST

A custom VPN protocol designed to be statistically indistinguishable from real HTTPS browsing — built to survive signature DPI, ML-based flow classifiers, and active probing.

> **Status:** Nothing works yet.

---

## Why

Existing protocols (OpenVPN, WireGuard, even VLESS+Reality) are increasingly detected and blocked by modern censorship infrastructure. Recent academic work (USENIX Security 2024 — Xue et al., *Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes*) shows >70% true-positive detection of Reality at <0.1% false-positive rate. Meanwhile, ML-based flow classifiers and potential whitelist regimes are escalating the arms race.

GHOST takes a different angle: **don't try to look like one specific protocol — look statistically identical to ordinary HTTPS browsing across every flow feature an ML classifier examines**.

## How

Five layers, each addressing a different detection vector:

| Layer | Purpose | Defends against |
|-------|---------|-----------------|
| **L1** TLS 1.3 + uTLS Chrome fingerprint | Handshake camouflage | JA3/JA3S signature DPI |
| **L2** HTTP/2 + reverse-proxy fallback | Application camouflage | Active probing, behavioral fingerprinting |
| **L3** Noise IK (constant-time) | Authentication | Timing side-channels, replay |
| **L4** Binary multiplexer | Stream framing | — (internal) |
| **L5** Statistical traffic shaper | Flow-level mimicry | ML classifiers, asymmetry/IAT analysis |

Full design rationale and threat model in [`research/`](research/). Wire format in [`docs/protocol.md`](docs/protocol.md).

## Project Layout

```
cmd/
  ghost-server/     server binary
  ghost-client/     client binary
  ghost-tools/      keygen, capture, classify utilities
internal/
  transport/        L1: TCP + uTLS
  camouflage/       L2: HTTP/2 wrapper
  auth/             L3: Noise IK handshake + sessions
  mux/              L4: stream multiplexer
  shaper/           L5: traffic shaper
  fallback/         reverse proxy for invalid auth
  tun/              TUN interface (Linux)
  config/           YAML config loader
  profile/          empirical traffic distributions
test/
  integration/      end-to-end tunnel tests
  detection/        ML detection harness (Python)
docs/
  protocol.md       wire format specification
research/           design context, threat model, prior art
```

## Build

```bash
make build         # builds ghost-server, ghost-client, ghost-tools
make test          # go test ./...
make clean
```

Or directly:

```bash
go build ./...
```

Requires Go 1.25+ (auto-bumped by `golang.org/x/crypto`). Linux only in v1.

## Out of Scope (v1)

CDN relay (Cloudflare Workers), stream migration, multi-client server, mobile clients, GUI, Windows/macOS clients. See plan for v2+ items.

## Legal & Ethical

GHOST is a censorship circumvention tool. Development is legal in most jurisdictions. **Deployment in jurisdictions that prohibit such tools (including the Russian Federation as of 2024) may carry legal risk for operators and users.** This project does not encourage breaking local laws — it exists to push the state of the art in network privacy research and to give users in restrictive environments a fighting chance.

This is not a public service. It is designed for small, private deployments by people who understand the risks.

## License

TBD.
