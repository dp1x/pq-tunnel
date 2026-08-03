# Tunnel Implementation Guide

## Status

Draft — Implementation Guide

## Purpose

This document defines engineering guidance for implementing the Tunnel protocol.

It answers:

> How should Tunnel be built safely?

This document defines:

- implementation principles
- software architecture guidance
- development workflow
- testing requirements
- security practices

This document does not define:

- protocol requirements
- cryptographic selections
- final handshake construction
- packet wire format

Those belong in:

- `PROTOCOL_SPEC.md`
- `DESIGN_DECISIONS.md`
- `CRYPTO_PROFILE.md`

---

# 1. Implementation Philosophy

Tunnel implementations MUST prioritize:

- correctness over optimization
- security over convenience
- explicit behaviour over hidden assumptions
- maintainability over unnecessary complexity

Implementations should preserve the core Tunnel principles:

- metadata resistance
- secure defaults
- cryptographic agility
- fail-secure behaviour
- explicit security tradeoffs

---

# 2. Implementation Architecture

A Tunnel implementation SHOULD separate responsibilities into independent components.

Recommended structure:

```text
+--------------------------------+
| Application Interface          |
+--------------------------------+
| Tunnel Session Manager         |
+--------------------------------+
| Protocol State Machine         |
+--------------------------------+
| Cryptographic Operations       |
+--------------------------------+
| Traffic Management             |
+--------------------------------+
| Network Transport              |
+--------------------------------+
```

Each component should have clear boundaries.

Security-critical components should not depend on unnecessary application logic.

---

# 3. Recommended Components

## 3.1 Application Interface

Responsible for:

- receiving application traffic
- providing data to Tunnel
- receiving decrypted traffic

The application interface MUST NOT handle:

- cryptographic operations
- packet authentication
- traffic shaping decisions

---

## 3.2 Session Manager

Responsible for:

- creating sessions
- maintaining session state
- tracking active connections
- handling lifecycle events

The session manager should maintain clear separation between:

- identity information
- session state
- connection identifiers

---

## 3.3 Protocol State Machine

The implementation SHOULD represent Tunnel states explicitly.

Example:

```text
INITIAL
    |
    v
HANDSHAKE
    |
    v
ESTABLISHED
    |
    v
REKEY
    |
    v
CLOSED
```

Invalid state transitions MUST be rejected.

State handling should avoid implicit behaviour.

---

## 3.4 Cryptographic Module

Responsible for:

- key generation
- key establishment operations
- authentication operations
- key derivation
- AEAD protection

The cryptographic module SHOULD:

- use approved libraries
- avoid custom primitives
- isolate sensitive operations

---

## 3.5 Traffic Management Module

Responsible for:

- scheduling
- padding behaviour
- cover traffic handling

Traffic management MUST preserve:

- explicit privacy settings
- documented security tradeoffs

It MUST NOT silently reduce metadata protection.

---

## 3.6 Transport Module

Responsible for:

- packet transmission
- receiving network data
- handling transport-specific behaviour

The transport module SHOULD avoid assumptions about:

- permanent network paths
- fixed IP addresses
- specific network environments

---

# 4. Secure Development Requirements

Implementations MUST:

- validate all external input
- reject invalid protocol states
- handle cryptographic failures safely
- avoid insecure fallbacks
- protect sensitive memory where possible

Implementations SHOULD:

- minimize privileged code
- reduce attack surface
- separate security-critical modules

---

# 5. Cryptographic Implementation Rules

Implementations MUST:

- use standardized cryptographic libraries
- follow the selected cryptographic profile
- maintain correct key separation
- prevent nonce reuse
- securely erase sensitive material where possible

Implementations MUST NOT:

- implement custom cryptographic primitives
- modify cryptographic algorithms
- bypass security checks for compatibility

---

# 6. Key Material Handling

Sensitive cryptographic material includes:

- identity keys
- handshake secrets
- session keys
- traffic keys

Implementations SHOULD:

- minimize key lifetime in memory
- avoid unnecessary copies
- erase sensitive material when no longer required

Key handling failures MUST fail securely.

---

# 7. Error Handling

Errors MUST be handled explicitly.

Examples:

```text
Authentication failure:
  Reject communication

Cryptographic failure:
  Terminate session

Invalid protocol state:
  Reject operation
```

Implementations MUST NOT:

- continue after security failures
- silently disable protections
- downgrade security mechanisms

---

# 8. Testing Requirements

Tunnel implementations SHOULD include:

## Unit Testing

Tests for:

- cryptographic wrappers
- state transitions
- packet handling
- configuration logic

---

## Integration Testing

Tests for:

- full session establishment
- encrypted communication
- rekeying behaviour
- failure handling

---

## Security Testing

Testing should include:

- malformed input testing
- replay testing
- downgrade testing
- authentication failure testing

---

## Fuzz Testing

Security-critical parsers SHOULD be fuzz tested.

Targets include:

- packet parsing
- protocol messages
- configuration handling

---

# 9. Performance Testing

Performance testing should measure:

- latency
- throughput
- memory usage
- CPU usage
- traffic shaping overhead

Performance optimization MUST NOT remove required security properties.

---

# 10. Logging and Observability

Implementations SHOULD provide useful diagnostics.

Logs MUST NOT expose:

- session keys
- private keys
- sensitive plaintext data
- authentication secrets

Security-sensitive information should be handled carefully.

---

# 11. Configuration Principles

Configuration options SHOULD be:

- explicit
- understandable
- documented

Security-related configuration changes MUST clearly communicate tradeoffs.

Implementations MUST NOT silently weaken:

- cryptographic protection
- authentication
- metadata protection

---

# 12. Deployment Considerations

Deployments should consider:

- key management
- secure updates
- trusted environments
- operational monitoring

Tunnel security depends on both:

- protocol correctness
- secure deployment practices

---

# 13. Implementation Validation

Before release, implementations SHOULD verify:

- protocol compliance
- cryptographic profile compliance
- interoperability
- security requirements
- failure behaviour

An implementation is not considered secure merely because encryption is present.

---

# 14. Future Development

Future improvements may include:

- additional transports
- performance optimizations
- new cryptographic profiles
- improved privacy mechanisms

Future changes MUST preserve:

- security guarantees
- protocol compatibility rules
- explicit tradeoffs

---

# Final Principle

Tunnel implementations should follow:

> Build the protocol exactly as specified, fail securely, and never trade hidden security for convenience.