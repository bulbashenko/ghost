# Research & Context Index

This directory contains all research and context gathered for designing a custom VPN protocol to bypass RKN/TSPU DPI and ML classifiers.

## Project Status

**Phase**: Planning (Plan Mode active)
**Goal**: Design and implement a VPN protocol better than VLESS+Reality, resistant to:
- Signature-based DPI (TSPU)
- ML-based flow classification
- Active probing
- Potential whitelist regimes

**Date context gathered**: 2026-04-09 / 2026-04-10
**Plan file**: `/home/bulbashenko/.claude/plans/streamed-gliding-dahl.md`

## Files in This Directory

| File | Purpose |
|------|---------|
| `00-INDEX.md` | This file — navigation and status |
| `01-rkn-detection-methods.md` | How RKN/TSPU detects VPNs (signatures, ML, probing) |
| `02-xtls-reality-analysis.md` | Why VLESS+Reality still gets detected |
| `03-ml-classifiers-and-evasion.md` | ML classifier state of the art + evasion techniques |
| `04-protocol-requirements.md` | Threat model + functional/security/AD requirements |
| `05-design-principles.md` | 12 core principles guiding all design decisions |
| `06-proposed-architecture.md` | 5-layer protocol architecture + wire format |
| `07-tech-stack.md` | Go dependencies, tools, project structure |

## Quick Reference — Key Facts

### Why Reality Fails
- Nested TLS handshake detectable (USENIX 2024, 70% TPR)
- Symmetric traffic ratio (~1:1) vs real HTTPS (~1:10)
- Long session duration vs short HTTPS
- Uniform TLS record sizes
- HMAC timing side-channels

### What ML Classifiers Look At
- 150+ flow features: packet sizes, IATs, bursts, ratios, duration
- Top performance: 99.81% accuracy (Decision Tree on SDN), 99.29% F1 (CS-BiGAN on obfs4)
- Key insight: Not looking for "your protocol", looking for "not normal HTTPS"

### Our Design Approach
1. **Single TLS only** (no nesting)
2. **Statistical traffic mimicry** (not just JA3)
3. **Forced asymmetric ratio** (1:5 via padding)
4. **Short sessions** with stream migration
5. **Noise IK pattern** in HTTP/2 body
6. **Constant-time auth** (no timing leaks)
7. **Fallback to real website** for active probing resistance
8. **CDN relay option** for whitelist bypass

### 5-Layer Stack
- L1: TLS 1.3 + uTLS (Chrome fingerprint) + optional CF Worker
- L2: HTTP/2 semantic camouflage + fallback server
- L3: Noise IK authentication (constant-time)
- L4: Binary multiplexer (streams)
- L5: Statistical traffic shaper (empirical distributions)

## Dependencies on External Context

- RKNHardering repo: https://github.com/xtclovver/RKNHardering (read-only reference)
- USENIX 2024 paper: Xue et al. "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes"
- Noise Protocol spec: https://noiseprotocol.org/noise.html
- Xray-core: https://github.com/XTLS/Xray-core
- uTLS: https://github.com/refraction-networking/utls

## Next Steps (Planned)

1. ✅ Gather research (DONE)
2. ✅ Define requirements + threat model (DONE)
3. ✅ Define design principles (DONE)
4. ✅ Propose architecture (DONE — subject to review)
5. ⬜ Design review with user — clarify open questions
6. ⬜ Launch Plan agent for detailed implementation plan
7. ⬜ Write final plan to `/home/bulbashenko/.claude/plans/streamed-gliding-dahl.md`
8. ⬜ ExitPlanMode → user approval
9. ⬜ Begin Phase 1 implementation (after approval)

## User Decisions (Confirmed)

| Decision | Choice |
|----------|--------|
| Project name | **GHOST** |
| v1 Scope | **MVP + Traffic Shaper** (Direct TCP, no CDN, no stream migration, ~6-8 weeks) |
| Platforms (v1) | **Linux server + Linux client** only |
| Detection testing | **Full ML harness** (CNN/XGBoost classifier, iterative testing) |
| Cover traffic | **Generic HTTPS browsing** (news sites, JSON APIs) |
| Fallback mode | **Reverse proxy to real website** (strongest probing resistance) |
| Infrastructure ready | **VPS outside RF + domain for TLS** (no RF test client yet) |
| Config format | **YAML** |

## Implications of Decisions

- **No CDN in v1** → focus on Direct TCP transport, real domain + Let's Encrypt cert
- **No stream migration in v1** → simpler mux, but connection lifecycle still needs random rotation
- **Generic HTTPS profile** → traffic shaper distributions captured from browsing news/social sites
- **Reverse proxy fallback** → server config must include `fallback_target` URL (e.g. https://example.org)
- **No RF test client** → detection validation relies on ML harness; real RF test deferred
- **Linux only** → use `golang.zx2c4.com/wireguard/tun` for TUN interface

## Open Questions Remaining

None blocking. Implementation can proceed.

## Conversation Summary

User's context:
- Wants custom VPN protocol (not Android app)
- Inspired by XTLS Reality architecture but going beyond
- Aware of white-list threat coming to Russia
- Aware of ML detectors being deployed
- Rejected running Plan agent initially — wanted context saved first
- Currently in Plan mode (cannot execute, only plan)

Approach taken:
- Launched 3 parallel Explore agents to gather research
- Compiled findings into structured research docs
- Now documenting everything before designing detailed plan

## How to Use These Docs

- **New session / context loss**: Start with `00-INDEX.md` (this file) → `04-protocol-requirements.md` → `06-proposed-architecture.md`
- **Design questions**: Check `05-design-principles.md` for guiding principles
- **Detection questions**: See `01-rkn-detection-methods.md` and `03-ml-classifiers-and-evasion.md`
- **Implementation questions**: See `07-tech-stack.md` and `06-proposed-architecture.md`
