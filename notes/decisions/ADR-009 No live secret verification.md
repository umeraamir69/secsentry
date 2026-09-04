---
tags:
  - adr
status: accepted
date: 2026-09-04
---

# ADR-009 No live secret verification

## Context

TruffleHog (and similar) often **use** a candidate secret against the vendor API to see if it is still valid. That is useful for IR, but it means the scanner **exfiltrates the secret** to a third party and can look like credential stuffing.

A student-hosted Next.js app doing that would be worse.

## Decision

SecSentry **never** sends a discovered secret (or fingerprint of a raw secret) to OpenAI, AWS, GitHub, or any other vendor to “check if it works.”

Confidence comes from format + entropy + context only. Reports say “looks like an Anthropic key,” not “this key is live.”

## Consequences

- Offline CLI is a real guarantee
- We will have more unconfirmed findings than TruffleHog — say so in the README
- Rotation guidance still applies: treat HIGH format matches as compromised until the owner revokes them
- Unique, defensible security stance for a Master’s project

## Related

- [[What makes this real and unique]]
- [[Threat model]]
- [[Competitor landscape]]
- [[Decisions]]
