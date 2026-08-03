# Tunnel Protocol Specification

## Status

Draft — Requirements Specification

## Purpose

This document defines the requirements and architectural structure of the Tunnel protocol.

It specifies:

- required security properties
- protocol responsibilities
- entities and roles
- lifecycle requirements
- component boundaries

This document does not define:

- specific cryptographic algorithms
- final handshake construction
- deployment-specific configurations
- implementation details

Those decisions belong in:

- `DESIGN_DECISIONS.md`
- `CRYPTO_PROFILE.md`
- `IMPLEMENTATION_GUIDE.md`

---

# 1. Introduction

Tunnel is a privacy-focused secure networking protocol designed around two primary objectives:

1. Long-term confidentiality against future cryptographic advances.
2. Reduction of metadata leakage from communication patterns.

Unlike traditional encrypted tunnels that primarily protect payload contents, Tunnel treats communication behaviour as a security concern.

Tunnel protects:

- transmitted data
- communication patterns
- traffic characteristics
- session behaviour

The core principle is:

> Protect the content and protect the pattern.

---

# 2. Scope

## 2.1 In Scope

Tunnel provides mechanisms for:

- authenticated communication
- secure session establishment
- encrypted data transport
- integrity protection
- replay protection
- session key management
- traffic shaping
- cover traffic support
- protocol versioning

---

## 2.2 Out of Scope

Tunnel does not attempt to protect against:

- compromised endpoints
- malware
- physical device compromise
- operating system compromise
- intentionally broken cryptographic primitives

Tunnel reduces metadata leakage but does not claim perfect anonymity against all observers.

---

# 3. Protected Assets

Tunnel protects the following assets:

- transported data
- communication metadata
- cryptographic state

Cryptographic state includes:

- session keys
- authentication state
- key derivation state

Protection of endpoint secrets is outside the protocol guarantee.

Tunnel does not protect against compromised endpoints or exposure of secrets already present on trusted systems.

---

# 4. Terminology

## Identity

The representation of a participant in the Tunnel system.

Identity mechanisms are defined separately from transport mechanisms.

---

## Identity Key

Long-lived cryptographic material used to establish or verify identity.

Exact usage is defined by the selected cryptographic profile.

---

## Ephemeral Key

Short-lived cryptographic material generated for a specific protocol interaction.

Ephemeral keys are used to provide forward secrecy properties.

---

## Session

A temporary authenticated communication relationship between Tunnel participants.

---

## Session Key

Short-lived cryptographic material used to protect active Tunnel communication.

---

## Connection ID

A session identifier used to associate packets with an existing Tunnel session.

A Connection ID:

- is not an identity
- is not authentication material
- must not be treated as a secret credential

---

## Rekey

The process of replacing active session protection keys.

---

# 5. Security Requirements

Tunnel implementations MUST provide the following security properties.

---

## 5.1 Confidentiality

Tunnel MUST protect transported data from unauthorized disclosure.

---

## 5.2 Authentication

Tunnel MUST provide mechanisms to verify communication peers according to the selected security model.

Authentication MUST protect against:

- impersonation
- unauthorized participation
- forged communication

The exact identity model is defined separately.

---

## 5.3 Integrity Protection

Tunnel MUST detect unauthorized modification of protected communication.

Modified packets MUST NOT be accepted as valid.

---

## 5.4 Forward Secrecy

Tunnel MUST provide forward secrecy.

Compromise of long-term key material MUST NOT automatically reveal previously protected sessions.

---

## 5.5 Harvest Now, Decrypt Later Resistance

Tunnel MUST consider future cryptographic capabilities.

Captured traffic SHOULD remain protected against future cryptographic attacks when the selected cryptographic profile remains secure and endpoints are uncompromised.

This requirement requires consideration of:

- key establishment
- authentication
- forward secrecy
- cryptographic agility

Tunnel does not claim protection against:

- compromised endpoints
- broken cryptographic primitives

---

## 5.6 Replay Protection

Tunnel MUST prevent attackers from successfully replaying previously accepted communication.

---

## 5.7 Fail Securely

Tunnel MUST fail in a secure state.

Examples:

```text
Authentication failure:
Reject connection

Cryptographic failure:
Terminate session

Invalid protocol state:
Reject operation
```

Tunnel MUST NOT:

- silently downgrade security
- silently disable protections
- use insecure fallback mechanisms

---

# 6. Entities and Roles

A Tunnel deployment consists of communicating entities.

At minimum:

```text
Tunnel Participant A
     |
     |
Tunnel Protocol
     |
     |
Tunnel Participant B
```

The protocol MUST define:

- identity handling
- session establishment
- secure communication lifecycle

Specific deployment roles are defined separately.

---

# 7. Protocol Architecture

Tunnel consists of several logical layers.

```text
+--------------------------------+
| Application Data               |
+--------------------------------+
| Tunnel Session Layer           |
+--------------------------------+
| Cryptographic Protection       |
+--------------------------------+
| Traffic Management Layer       |
+--------------------------------+
| Network Transport              |
+--------------------------------+
```

Logical layer separation does not define the final packet processing order.

The exact ordering of:

- scheduling
- padding
- encryption
- transport operations

is determined by later protocol design decisions.

---

## 7.1 Application Layer

Provides data to be transported through Tunnel.

The application layer is not responsible for:

- encryption
- authentication
- traffic shaping

---

## 7.2 Session Layer

Responsible for:

- maintaining Tunnel sessions
- managing connection state
- handling lifecycle events

---

## 7.3 Cryptographic Layer

Responsible for:

- confidentiality
- integrity
- authentication
- key management operations

Specific algorithms are defined separately.

---

## 7.4 Traffic Management Layer

Responsible for reducing metadata leakage through:

- traffic shaping
- padding
- cover traffic mechanisms

---

## 7.5 Transport Layer

Provides packet delivery.

Tunnel SHOULD avoid depending on assumptions about:

- fixed network paths
- permanent IP addresses
- specific MTU sizes

---

# 8. Connection Lifecycle

A Tunnel connection follows a defined lifecycle.

High-level states:

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

---

## 8.1 Initial State

Before communication begins:

- no session exists
- no application data may be transmitted

---

## 8.2 Handshake State

The handshake establishes the required security context.

The handshake MUST provide:

- peer authentication
- secure key establishment
- protocol compatibility validation

---

## 8.3 Established State

During an active session Tunnel provides:

- encrypted transport
- integrity protection
- replay protection
- traffic management

---

## 8.4 Closed State

A closed session MUST NOT accept further protected communication.

---

# 9. Handshake Requirements

The handshake mechanism MUST provide:

- authenticated session establishment
- forward secrecy
- resistance against future cryptographic threats
- agreement on protocol parameters

The handshake MUST define:

- participant roles
- key material usage
- authentication process
- transcript protection
- failure behaviour

Specific handshake construction is defined through later design decisions.

---

# 10. Session Requirements

Active sessions MUST provide:

- unique session protection keys
- replay protection
- connection identification
- secure state management

Sessions MUST NOT depend permanently on source network addresses.

This allows support for:

- NAT environments
- changing network paths
- roaming scenarios

---

# 11. Packet Requirements

Tunnel packets MUST provide:

- session association
- integrity verification
- confidentiality protection
- replay detection information
- authenticated associated data handling

The packet format MUST define:

- header structure
- protected fields
- authenticated fields
- sequencing mechanism

Exact wire format is defined after protocol design decisions are finalized.

---

# 12. Traffic Shaping Requirements

Metadata resistance is a core Tunnel objective.

Tunnel MUST consider leakage from:

- timing
- packet sizes
- traffic volume
- idle periods
- burst behaviour
- communication direction

---

## 12.1 Default Behaviour

The default Tunnel configuration SHOULD prioritize metadata resistance.

The default design direction is:

- fixed traffic shaping
- cover traffic enabled

---

## 12.2 Configurable Modes

Implementations MAY provide different operating modes.

Any reduction in privacy guarantees MUST be:

- explicit
- visible
- documented

Tunnel MUST NOT silently weaken metadata protections.

---

# 13. Rekeying Requirements

Tunnel MUST support session rekeying.

Rekeying MUST support Tunnel's forward secrecy objectives.

The rekey process SHOULD:

- limit cryptographic exposure windows
- maintain session security
- preserve communication continuity

The rekey process MUST define:

- trigger conditions
- transition behaviour
- failure handling

---

# 14. Error Handling

Tunnel MUST reject:

- invalid packets
- failed authentication
- invalid state transitions
- unsupported protocol versions

Errors MUST NOT cause insecure fallback behaviour.

---

# 15. Versioning

Tunnel MUST support protocol version identification.

Version negotiation MUST:

- prevent incompatible communication
- prevent downgrade attacks
- maintain explicit compatibility rules

---

# 16. Future Design Decisions

The following areas require separate design decisions:

- handshake construction
- identity model
- cryptographic profile
- packet encoding
- nonce construction
- rekey timing
- advanced traffic scheduling

These decisions MUST preserve the requirements defined in this document.

---

# 17. Document Boundary

This specification defines:

- what Tunnel must provide
- required security properties
- protocol responsibilities
- architectural boundaries

This specification does not define:

- how Tunnel achieves these properties
- selected cryptographic algorithms
- final handshake protocol
- final packet byte layout
- implementation details

Those decisions belong in:

- `DESIGN_DECISIONS.md`
- `CRYPTO_PROFILE.md`
- `IMPLEMENTATION_GUIDE.md`