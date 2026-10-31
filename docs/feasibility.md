# HyperOne — Feasibility Assessment

Status: draft v0.1 · 2026-10-31

## Bottom line

| Question | Answer |
|---|---|
| Can we build a protocol that *cannot* be detected? | **No.** No protocol is undetectable against a censor willing to accept enough collateral damage (e.g. allowing only approved sites, or blocking all foreign datacenter IP ranges). Treat any claim of "undetectable" as marketing. |
| Can we build one that is **meaningfully harder to block than VLESS + REALITY + Vision**? | **Plausibly** — but the gains are mostly *not* in the cryptography or handshake, which REALITY has largely solved. |
| Should we just stack every feature from every protocol? | **No.** Every added feature is one more thing that can be fingerprinted. "Combine the best ideas" is not the same as piling on mechanisms. |

The realistic design goal is economic, not absolute: **make the cheapest reliable way to block the protocol also block a lot of traffic the censor wants to keep.**

## Where to go next

The serious work on this happens in the open, with people who measure against real censors:

- **Published measurement research** — the GFW Report team's papers (e.g. at USENIX Security), and the Tor Project's anti-censorship research.
- **Existing projects** — Xray-core, sing-box, and Tor's pluggable transports, where design discussion is public and tested.

## Note on scope

This repository is being set up for research into censorship-resistant transport.
A detailed, step-by-step design of how to defeat specific detection methods is out of
scope for what is written here; this file records the high-level feasibility framing only.
