# Tunnel Cryptographic Profile

## Status

Draft — Cryptographic Profile

## Purpose

This document defines the cryptographic requirements and selection boundaries for the Tunnel protocol.

It answers:

> What cryptographic mechanisms and properties does Tunnel require?

This document defines:

- cryptographic roles
- security requirements
- algorithm selection boundaries
- key management principles
- cryptographic lifecycle requirements

This document does not define:

- final handshake construction
- packet formats
- protocol message flow
- implementation details

Those belong in:

- `PROTOCOL_SPEC.md`
- `DESIGN_DECISIONS.md`
- `IMPLEMENTATION_GUIDE.md`

---

# 1. Cryptographic Architecture

Tunnel separates cryptographic responsibilities into independent components.

The cryptographic architecture consists of:

```text
Identity Authentication
        |
        v
Key Establishment
        |
        v
Key Derivation
        |
        v
Session Keys
        |
        v
Traffic Keys
        |
        v
AEAD Protection
```

Each component has a separate purpose.

Tunnel does not treat encryption, authentication, and key establishment as the same function.

---

# 2. Cryptographic Requirements

Tunnel cryptographic mechanisms MUST provide:

- confidentiality
- integrity protection
- authentication support
- forward secrecy
- resistance against harvest-now-decrypt-later threats
- cryptographic agility

Cryptographic mechanisms MUST be:

- publicly reviewed
- based on established research
- independently analyzable

Tunnel MUST NOT rely on:

- proprietary cryptography
- secret algorithms
- unreviewed primitives

---

# 3. Identity Authentication

## Purpose

Identity authentication establishes confidence in the identity of communicating Tunnel participants.

Authentication mechanisms provide:

- peer identity verification
- protection against impersonation
- authenticated protocol participation

The exact identity model is defined through:

- `DESIGN_DECISIONS.md`
- `PROTOCOL_SPEC.md`

---

## Identity Keys

Identity keys represent long-term cryptographic identity material.

Identity keys may be used for:

- authentication
- establishing trust relationships
- verifying communication peers

Identity key lifecycle and usage rules are defined separately.

Long-term identity keys MUST NOT directly protect application traffic.

---

# 4. Key Establishment

## Purpose

Key establishment creates shared cryptographic material between Tunnel participants.

The key establishment process MUST support:

- forward secrecy
- resistance against future cryptographic threats
- cryptographic agility

---

## Post-Quantum Key Establishment

Tunnel requires PQ-capable key establishment.

The selected mechanism must consider:

- harvest-now-decrypt-later threats
- future cryptographic capabilities
- long-term confidentiality requirements

The ML-KEM family is considered as a possible post-quantum key establishment mechanism.

Final algorithm selection belongs to the Tunnel v1 cryptographic profile.

---

## Forward Secrecy Clarification

Forward secrecy depends on the complete key establishment construction.

A post-quantum KEM alone does not automatically provide forward secrecy.

Forward secrecy requires appropriate use of:

- ephemeral cryptographic material
- key derivation
- session lifecycle management

---

# 5. Cryptographic Algorithm Selection

Tunnel separates:

```text
Cryptographic Requirements
        from
Specific Algorithm Selection
```

The profile defines required properties.

The final Tunnel v1 suite defines the selected algorithms.

---

# 6. Post-Quantum Parameter Selection

The ML-KEM family provides multiple security parameter levels.

Examples:

| Parameter   | Security Level                      | Intended Tradeoff       |
| ----------- | ----------------------------------- | ----------------------- |
| ML-KEM-512  | Lower security / higher performance | Efficiency focused      |
| ML-KEM-768  | Balanced security and performance   | General purpose         |
| ML-KEM-1024 | Higher security / larger cost       | Maximum security margin |

The final parameter selection is a Tunnel v1 cryptographic decision.

Selection must consider:

- threat model requirements
- performance constraints
- implementation maturity
- long-term security expectations

---

# 7. Authentication Cryptography

Authentication cryptography is separate from key establishment.

The protocol must distinguish:

```text
Key Establishment
        ≠
Authentication
```

Key establishment creates shared secrets.

Authentication verifies participant identity.

The exact authentication mechanism is defined through later design decisions.

Possible mechanisms may include:

- signature-based authentication
- other authenticated identity mechanisms

The final selection belongs in the Tunnel v1 cryptographic profile.

---

# 8. Symmetric Encryption

Tunnel uses authenticated encryption with associated data (AEAD) for traffic protection.

AEAD provides:

- confidentiality
- integrity
- authenticated data protection

AEAD protection applies to:

- encrypted tunnel traffic
- authenticated protocol fields

The selected AEAD mechanism must provide:

- strong security analysis
- efficient implementation
- long-term confidence

---

## Nonce Requirements

AEAD nonce handling is security-critical.

Tunnel requires:

- unique nonce usage
- correct nonce construction
- prevention of accidental reuse

Some AEAD mechanisms may reduce the impact of implementation mistakes where supported.

However:

Nonce uniqueness remains a mandatory requirement.

Exact nonce construction belongs in:

- `PROTOCOL_SPEC.md`

---

# 9. Key Derivation

Tunnel uses cryptographic key derivation to separate different cryptographic purposes.

Key derivation provides:

- key separation
- controlled generation of session material
- reduced risk from key reuse

Derived keys SHOULD have distinct purposes.

Examples:

```text
Handshake Material
        |
        v
Session Keys
        |
        v
Traffic Keys
```

Exact derivation rules belong in the protocol design.

---

# 10. Key Hierarchy

Tunnel separates cryptographic material by lifecycle and purpose.

The intended hierarchy is:

```text
Identity Keys
        |
        v
Handshake Secrets
        |
        v
Session Keys
        |
        v
Traffic Keys
        |
        v
Packet Protection
```

Each layer has separate responsibilities.

Identity keys:

- represent long-term identity

Handshake secrets:

- establish session security context

Session keys:

- protect active Tunnel sessions

Traffic keys:

- protect transported data

The exact derivation process is defined through protocol decisions.

---

# 11. Rekeying

Tunnel supports cryptographic rekeying.

Rekeying provides:

- reduced cryptographic exposure windows
- improved session security
- continued forward secrecy objectives

The rekey process must define:

- key replacement behaviour
- transition handling
- failure behaviour

Exact rekey protocol behaviour belongs in:

- `PROTOCOL_SPEC.md`

---

# 12. Randomness Requirements

Tunnel cryptographic operations require secure randomness.

Random number generation is required for:

- key generation
- ephemeral material
- cryptographic operations

Failure of required randomness sources MUST result in secure failure.

Tunnel MUST NOT continue using predictable cryptographic material.

---

# 13. Cryptographic Agility

Tunnel is designed for long-term operation.

Cryptographic algorithms may eventually become:

- deprecated
- weakened
- replaced

Tunnel separates:

- protocol security requirements
- cryptographic implementations

Cryptographic components should be replaceable without invalidating the overall protocol architecture.

Algorithm replacement may require:

- protocol version changes
- updated cryptographic profiles
- compatibility decisions

However, replacement should not require redesigning Tunnel's security model.

---

# 14. Tunnel v1 Cryptographic Profile

> **v0.2.0-alpha pinned suite (current implementation).** The placeholders below
> were resolved for v0.2.0-alpha and are pinned in code; they remain
> *replaceable* (§13) without redesigning the security model. Selection is
> anchored to external known-answer vectors per D21 (RFC 8439, RFC 5869,
> RFC 7748, Wycheproof ML-KEM-768/ML-DSA-65) and to D13–D15/D19. Future
> algorithm replacement may require a protocol version change (D13).

```text
Key Establishment: ML-KEM-768 + X25519 hybrid (HKDF-SHA256 shared-secret merge)
Authentication:     ML-DSA-65, roster-pinned mutual authentication (no anon mode)
AEAD:               ChaCha20-Poly1305 (192-bit nonce = 4-byte KDF prefix ‖ 8-byte u64 counter)
KDF:                HKDF-SHA256 with per-purpose domain-separation labels (-v1/-v2)
```

The final selection must satisfy:

- Tunnel threat model requirements
- protocol security requirements
- cryptographic design principles

---

# Final Principle

Tunnel follows the rule:

> Use established cryptography, separate responsibilities, and preserve the ability to evolve.

The cryptographic profile must preserve:

- long-term confidentiality
- forward secrecy
- authentication
- metadata protection goals
- cryptographic agility