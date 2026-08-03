# Tunnel Threat Model

## 1. Purpose

Tunnel is a privacy-focused networking protocol designed around two primary security objectives:

1. **Harvest Now, Decrypt Later (HNDL) resistance**
2. **Metadata resistance**

Tunnel is designed for environments where communication may be observed, collected, analyzed, and potentially attacked by future adversaries.

The threat model defines:

- what Tunnel protects,
- what attackers are considered,
- what assumptions exist,
- what guarantees Tunnel attempts to provide,
- and what is explicitly outside the scope.

Tunnel focuses not only on protecting the contents of communication, but also reducing information leakage from communication patterns.

---

# 2. Protected Assets

Tunnel protects several categories of information.

---

## 2.1 Communication Confidentiality

Tunnel protects the contents of communication from unauthorized access.

This includes:

- transmitted data,
- application payloads,
- exchanged information.

The objective is that unauthorized observers cannot read protected communication.

---

## 2.2 Communication Authenticity

Tunnel protects communication integrity and identity verification.

This includes protection against:

- packet modification,
- forged communication,
- impersonation,
- malicious injection.

Confidentiality alone is insufficient.

A secure system must ensure that received data is both:

- secret,
- and authentic.

---

## 2.3 Metadata Privacy

Tunnel treats metadata as a primary security concern.

Metadata includes information such as:

- packet timing,
- packet sizes,
- traffic volume,
- idle periods,
- communication patterns,
- directionality,
- session behaviour,
- traffic bursts.

Encrypted content may still reveal sensitive information through observable patterns.

Tunnel therefore considers traffic analysis a first-class threat.

---

## 2.4 Cryptographic State

Tunnel protects cryptographic material required for secure operation.

This includes:

- session keys,
- key derivation state,
- authentication state,
- cryptographic parameters,
- temporary secrets.

Exposure of cryptographic state may compromise security properties.

Tunnel therefore considers:

- secure key handling,
- key lifecycle management,
- rekeying,
- secure erasure,

as important parts of the security model.

---

# 3. Security Assumptions

Tunnel assumes:

- endpoints run trusted Tunnel implementations,
- cryptographic randomness generation is secure,
- selected cryptographic primitives remain secure,
- operating systems provide basic memory isolation,
- users protect authentication credentials,
- implementation vulnerabilities are not present.

Tunnel cannot provide security if endpoints are fully compromised.

A compromised endpoint may expose:

- plaintext data,
- keys,
- user activity,
- application behaviour.

---

# 4. Adversary Model

Tunnel considers multiple classes of adversaries.

---

# 4.1 Passive Network Observer

The attacker can:

- observe network traffic,
- capture packets,
- store traffic,
- analyze timing and patterns.

Examples:

- ISP-level observers,
- network monitoring systems,
- malicious WiFi observers.

The attacker cannot:

- modify traffic,
- inject packets,
- compromise endpoints.

Tunnel aims to reduce both content exposure and metadata leakage against this attacker.

---

# 4.2 Harvest Now, Decrypt Later (HNDL) Adversary

The attacker:

1. records encrypted traffic today,
2. stores it,
3. attempts decryption in the future using improved technology.

This includes future advances such as:

- quantum computing,
- cryptanalytic improvements,
- stronger computational resources.

Tunnel aims to provide protection against future decryption attempts when:

- the selected cryptographic profile remains secure,
- endpoints remain uncompromised,
- protocol assumptions remain valid.

---

# 4.3 Active Network Attacker

The attacker can:

- modify packets,
- inject packets,
- replay packets,
- drop packets,
- interfere with communication.

Tunnel must protect against:

- forged messages,
- unauthorized modification,
- replay attacks,
- downgrade attempts.

---

# 4.4 Local Attacker

The attacker has access to the local environment.

Examples:

- malicious local network users,
- compromised local infrastructure,
- nearby attackers.

Capabilities may include:

- observing local traffic,
- attempting interference,
- fingerprinting communication.

Tunnel does not protect against a fully compromised endpoint.

---

# 4.5 Infrastructure-Level Attacker

The attacker may compromise or observe parts of the networking infrastructure.

Examples:

- compromised servers,
- malicious hosting providers,
- network infrastructure observers.

The impact depends on deployment architecture.

Infrastructure compromise may expose:

- availability information,
- operational metadata,
- server-side observations.

However, compromise of infrastructure does not automatically imply compromise of endpoint cryptographic guarantees.

---

# 5. Quantum Threat Model

Tunnel considers future quantum computers as a long-term threat.

The primary concern is:

**Harvest Now, Decrypt Later.**

An attacker may collect encrypted traffic today and attempt decryption when stronger capabilities become available.

Tunnel therefore requires consideration of:

- post-quantum key establishment,
- post-quantum authentication,
- forward secrecy,
- cryptographic agility.

Symmetric encryption security and asymmetric cryptographic security are considered separately.

---

# 6. Metadata Threat Model

Tunnel considers traffic analysis a major threat.

An observer may attempt to infer information from:

- packet sizes,
- packet timing,
- traffic volume,
- idle periods,
- bursts,
- session duration,
- directionality.

Tunnel aims to reduce metadata leakage through mechanisms such as:

- consistent packet structures,
- controlled timing behaviour,
- traffic shaping,
- cover traffic.

Metadata resistance is a primary design goal.

---

# 7. Active Attack Considerations

Tunnel considers active attacks including:

- replay attacks,
- packet injection,
- packet modification,
- downgrade attempts,
- protocol manipulation,
- traffic probing.

Security mechanisms must ensure:

- authenticated communication,
- correct protocol state handling,
- rejection of invalid states,
- no silent fallback to weaker security.

---

# 8. Out of Scope

Tunnel does not attempt to protect against:

- fully compromised endpoints,
- malware on user devices,
- malicious applications with endpoint access,
- physical compromise of secured devices,
- insecure user authentication practices,
- failures of underlying operating systems.

Tunnel protects communication security, not general device security.

---

# 9. Security Priorities

Tunnel prioritizes:

1. Long-term confidentiality (HNDL resistance)
2. Metadata resistance
3. Authentication and integrity
4. Secure defaults
5. Transparency
6. Deployment practicality
7. Performance

Performance optimizations must not silently weaken security properties.

---

# 10. Requirements Derived From Threat Model

The threat model requires Tunnel to consider:

## HNDL Protection

- post-quantum capable cryptography,
- forward secrecy,
- cryptographic agility,
- secure key lifecycle management.

## Metadata Protection

- traffic pattern resistance,
- timing resistance,
- size resistance,
- configurable traffic shaping.

## Secure Operation

- authenticated communication,
- replay protection,
- downgrade resistance,
- fail-secure behaviour.

## User Control

Any security reduction must be:

- intentional,
- visible,
- documented,
- reversible.

---

# 11. Security Claims

Tunnel is designed to provide:

- protection against unauthorized reading of communication,
- protection against unauthorized modification,
- improved resistance against future cryptographic advances,
- reduced metadata leakage compared with conventional encrypted tunnels.

These properties depend on:

- secure implementations,
- secure cryptographic profiles,
- uncompromised endpoints,
- valid security assumptions.

No cryptographic system can guarantee security if its underlying assumptions fail.

---

# 12. Threat Model Evolution

The threat model must evolve as:

- cryptographic research advances,
- attacker capabilities change,
- deployment environments change,
- new vulnerabilities are discovered.

The core objectives remain:

- resist long-term cryptographic threats,
- minimize metadata leakage,
- use transparent security engineering,
- preserve user control.

Implementation details may change.

Security objectives remain stable.