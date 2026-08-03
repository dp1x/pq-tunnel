# Tunnel Project Charter

## Document Purpose

This document defines the fundamental goals, principles, and boundaries of the Tunnel project.

It describes:

- why Tunnel exists,
- what guarantees it attempts to provide,
- what principles cannot be violated,
- how future engineering decisions should be evaluated.

This document intentionally avoids locking specific implementations.

Algorithms, parameters, packet formats, and engineering choices may change.

The principles and guarantees are the foundation.

---

# 1. Project Mission

Tunnel is a privacy-focused networking protocol designed around two primary objectives:

1. Harvest Now, Decrypt Later (HNDL) resistance
2. Metadata resistance

Tunnel exists because modern encrypted networking has a fundamental limitation:

Encryption protects the contents of communication.

It does not automatically protect:

- communication patterns,
- traffic characteristics,
- timing information,
- long-term confidentiality against future cryptographic advances.

Tunnel therefore treats both cryptographic security and metadata privacy as first-class requirements.

---

# 2. Core Security Goals

## 2.1 HNDL Resistance

Tunnel must be designed against adversaries who:

1. Observe and collect traffic today.
2. Store encrypted traffic for future analysis.
3. Attempt decryption when future technology becomes available.

The protocol must consider:

- quantum computing advances,
- future cryptanalysis,
- long-term confidentiality requirements.

HNDL protection requires a complete security lifecycle:

- secure key establishment,
- strong authentication,
- forward secrecy,
- key rotation,
- cryptographic agility.

Protecting only current communication is insufficient.

Historical traffic must remain protected.

---

## 2.2 Metadata Resistance

Tunnel considers metadata a security concern.

Metadata includes:

- packet timing,
- packet size,
- traffic volume,
- idle periods,
- communication patterns,
- directionality,
- session behaviour,
- observable fingerprints.

A system can have perfect encryption while still leaking sensitive information through traffic patterns.

Tunnel therefore aims to reduce metadata leakage through:

- consistent traffic characteristics,
- traffic shaping,
- cover traffic,
- resistance against traffic analysis.

---

# 3. Privacy Priority

Tunnel follows this principle:

> Privacy and security guarantees are more important than maximum performance.

Performance is a configurable tradeoff.

The system must never silently reduce privacy because of:

- bandwidth limitations,
- CPU limitations,
- battery limitations,
- convenience.

Any reduction in security or privacy must be:

- intentional,
- visible,
- documented,
- reversible.

---

# 4. Security Over Convenience

Tunnel follows conservative security engineering.

The project prefers:

- public standards,
- open algorithms,
- independent analysis,
- reproducible implementations,
- proven cryptographic constructions.

Tunnel must never rely on:

- secret cryptography,
- undocumented security mechanisms,
- hidden behaviour,
- security through obscurity.

Security comes from mathematics, engineering, and public review.

---

# 5. Encryption and Authentication

Encryption and authentication solve different problems.

Encryption provides:

- confidentiality,
- protection against unauthorized reading.

Authentication provides:

- integrity,
- protection against modification,
- protection against impersonation,
- verification of legitimate communication.

Tunnel requires both.

A system that encrypts without authentication is incomplete.

A system that authenticates without confidentiality is incomplete.

Authenticated encryption is a fundamental requirement.

---

# 6. Standards-Based Cryptography

Tunnel cryptography must use publicly reviewed and widely analyzed constructions.

Cryptographic choices should prioritize:

- public standards,
- security analysis,
- independent review,
- mature implementations,
- constant-time implementations where required.

Tunnel does not invent cryptography.

Cryptographic components are replaceable.

Security principles are not.

---

# 7. Cryptographic Agility

Tunnel must be able to evolve as cryptography evolves.

Specific algorithms are implementation profiles, not permanent requirements.

Future changes may replace:

- key exchange mechanisms,
- signature algorithms,
- encryption algorithms,
- supporting primitives.

However, replacements must preserve the project's guarantees.

---

# 8. Parameters Are Not Guarantees

A core Tunnel principle:

> Parameters control tradeoffs. They do not define guarantees.

Examples:

A higher traffic rate may improve metadata resistance.

A lower traffic rate may reduce bandwidth usage.

A larger packet size may improve efficiency.

A smaller packet size may improve deployment compatibility.

Changing parameters must never silently change the security model.

The user must understand the consequence of choices.

---

# 9. Secure by Default

The default configuration must represent the intended Tunnel security model.

Tunnel must not automatically weaken:

- encryption,
- authentication,
- HNDL protection,
- metadata protection.

The software must not optimize by silently reducing security.

Lower-security configurations may exist only when:

- explicitly chosen,
- clearly explained,
- reversible.

---

# 10. Modular Architecture

Tunnel follows a modular LEGO-style design philosophy.

Components should be replaceable and independently improved.

Examples:

- cryptographic modules,
- traffic scheduling modules,
- transport modules,
- configuration profiles,
- deployment modes.

However:

Modularity must not allow components to silently violate core guarantees.

Every module must clearly define:

- what it changes,
- what it preserves,
- what tradeoffs it introduces.

---

# 11. Fail Securely

Tunnel must fail securely.

Security failures must not result in insecure operation.

Examples:

Authentication failure:

- reject communication.

Cryptographic failure:

- terminate safely.

Missing randomness:

- abort operation.

Invalid protocol state:

- reject.

Unsafe downgrade:

- reject.

A failed secure connection is preferable to a successful insecure connection.

---

# 12. Explicit Tradeoffs

Security reductions must follow strict rules.

Any tradeoff must be:

## Intentional

Chosen deliberately by the user or operator.

## Visible

The impact must be understandable.

## Documented

The reason and consequences must be recorded.

## Reversible

Secure defaults must always be recoverable.

Tunnel must never contain hidden compromises.

---

# 13. User Control

Tunnel treats users as capable operators.

The system should provide:

- secure defaults,
- understandable configuration,
- advanced controls.

Users may configure tradeoffs involving:

- performance,
- latency,
- bandwidth,
- security profiles.

The software should clearly distinguish:

- convenience settings,
- performance settings,
- security guarantees.

---

# 14. No Hidden Behaviour

Tunnel must behave exactly as documented.

The software must not:

- silently disable protections,
- silently downgrade cryptography,
- silently reduce privacy,
- silently change security modes,
- hide important tradeoffs.

What the user configures is what happens.

---

# 15. Non-Goals

Tunnel intentionally does not attempt to solve every security problem.

Tunnel does not aim to provide:

- complete anonymity networks like Tor,
- guaranteed censorship resistance,
- protection against compromised endpoints,
- protection against malware controlling the device,
- physical device security,
- replacement for operating system security,
- proprietary cryptography.

Tunnel focuses on:

- HNDL-resistant secure communication,
- metadata-resistant networking,
- authenticated encrypted communication,
- transparent privacy engineering.

---

# 16. Design Review Principles

Every major design decision must answer:

## HNDL

- Does this weaken long-term confidentiality?
- Does this reduce forward secrecy?
- Does this increase compromise impact?
- Does this introduce downgrade risks?

## Metadata

- Does this leak timing?
- Does this leak packet characteristics?
- Does this create fingerprints?
- Does this reveal communication behaviour?

## Engineering

- Does this increase attack surface?
- Does this create hidden assumptions?
- Does this create unnecessary complexity?
- Can the same goal be achieved more simply?

## User Impact

- Is the tradeoff visible?
- Can users understand it?
- Can secure defaults be restored?

---

# 17. Final Principle

Tunnel exists because secure communication requires more than hiding message contents.

It must consider:

- what future technology can recover,
- what observers can learn from metadata,
- how privacy survives over time,
- how security behaves under failure.

Tunnel therefore prioritizes:

**HNDL Resistance + Metadata Resistance + Transparent Security Engineering**

The implementation may evolve.

The guarantees remain.