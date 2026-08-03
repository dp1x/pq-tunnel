//! Explicit Tunnel connection state machine.
//!
//! PROTOCOL_SPEC §8 defines the connection lifecycle as
//! `INITIAL → HANDSHAKE → ESTABLISHED → REKEY → CLOSED`.
//! IMPLEMENTATION_GUIDE §3.3 requires states to be represented explicitly and
//! invalid state transitions to be rejected ("State handling should avoid
//! implicit behaviour").
//!
//! This module is a pure state machine: it carries no session state and makes
//! no I/O decisions.  [`crate::WireSession`] owns the mutable connection and
//! delegates every lifecycle decision to this machine, so a session cannot
//! silently enter a state the protocol does not allow.

use std::fmt;

/// The connection lifecycle states from PROTOCOL_SPEC §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolState {
    /// Before communication begins: no session exists and no application data
    /// may be transmitted (§8.1).
    Initial,
    /// Handshake in progress: establishing the security context (§8.2).
    Handshake,
    /// Active session: encrypted transport, integrity, replay and traffic
    /// management are in effect (§8.3).
    Established,
    /// Key rotation in progress (§8 lifecycle; §13 rekeying).
    Rekey,
    /// Terminal: a closed session MUST NOT accept further protected
    /// communication (§8.4).
    Closed,
}

impl ProtocolState {
    /// All states, in lifecycle order (for exhaustive iteration/tests).
    pub const ALL: [ProtocolState; 5] = [
        ProtocolState::Initial,
        ProtocolState::Handshake,
        ProtocolState::Established,
        ProtocolState::Rekey,
        ProtocolState::Closed,
    ];

    /// Whether this state permits no further transitions.
    pub const fn is_terminal(self) -> bool {
        matches!(self, ProtocolState::Closed)
    }

    /// Allowed transitions per the PROTOCOL_SPEC §8 lifecycle:
    ///
    /// ```text
    /// Initial     → Handshake
    /// Handshake   → Established | Closed
    /// Established → Rekey | Closed
    /// Rekey       → Established | Closed
    /// Closed      → (none)
    /// ```
    ///
    /// `Rekey → Established` preserves communication continuity across a key
    /// rotation (§13: "preserve communication continuity"); every other arc in
    /// the documented lifecycle is rejected.
    pub const fn can_transition_to(self, to: ProtocolState) -> bool {
        matches!(
            (self, to),
            (ProtocolState::Initial, ProtocolState::Handshake)
                | (ProtocolState::Handshake, ProtocolState::Established)
                | (ProtocolState::Handshake, ProtocolState::Closed)
                | (ProtocolState::Established, ProtocolState::Rekey)
                | (ProtocolState::Established, ProtocolState::Closed)
                | (ProtocolState::Rekey, ProtocolState::Established)
                | (ProtocolState::Rekey, ProtocolState::Closed)
        )
    }

    /// Attempt a transition, returning `Ok(to)` on success or the rejected
    /// transition on failure.  Fails closed: an invalid transition never
    /// leaves the machine in a different state.
    pub fn transition(self, to: ProtocolState) -> Result<ProtocolState, InvalidTransition> {
        if self.can_transition_to(to) {
            Ok(to)
        } else {
            Err(InvalidTransition { from: self, to })
        }
    }

    /// Stable, non-allocating name for logging (`tracing`, metrics).
    pub const fn as_str(self) -> &'static str {
        match self {
            ProtocolState::Initial => "initial",
            ProtocolState::Handshake => "handshake",
            ProtocolState::Established => "established",
            ProtocolState::Rekey => "rekey",
            ProtocolState::Closed => "closed",
        }
    }
}

impl fmt::Display for ProtocolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A state transition that is not part of the documented lifecycle
/// (PROTOCOL_SPEC §8, IMPLEMENTATION_GUIDE §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid state transition: {from} -> {to}")]
pub struct InvalidTransition {
    /// The state the session was in.
    pub from: ProtocolState,
    /// The state that was illegally requested.
    pub to: ProtocolState,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-written expected transition table for the §8 lifecycle, indexed
    /// `[from_index][to_index]` where the index order is `ProtocolState::ALL`.
    /// This is the *oracle* for the tests — it is derived directly from the
    /// documented lifecycle diagram, NOT from the implementation under test, so
    /// a mistake in `can_transition_to` cannot make the tests pass silently.
    const EXPECTED_TRANSITIONS: [[bool; 5]; 5] = [
        // from \ to:        Initial  Handshake  Established  Rekey  Closed
        /* Initial */
        [false, true, false, false, false],
        /* Handshake */ [false, false, true, false, true],
        /* Established */ [false, false, false, true, true],
        /* Rekey */ [false, false, true, false, true],
        /* Closed */ [false, false, false, false, false],
    ];

    fn idx(s: ProtocolState) -> usize {
        ProtocolState::ALL
            .iter()
            .position(|&x| x == s)
            .expect("state is in ALL")
    }

    /// Every (from, to) pair must match the documented lifecycle table, for both
    /// `can_transition_to` and `transition` (which must fail closed, returning
    /// the exact transition in the error).
    #[test]
    fn transition_matrix_matches_documented_lifecycle() {
        for from in ProtocolState::ALL {
            for to in ProtocolState::ALL {
                let expected = EXPECTED_TRANSITIONS[idx(from)][idx(to)];
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "{from} -> {to} must be {}",
                    if expected { "allowed" } else { "rejected" }
                );
                match from.transition(to) {
                    Ok(got) => {
                        assert!(expected, "{from} -> {to} must be rejected, got Ok({got})");
                        assert_eq!(got, to);
                    }
                    Err(e) => {
                        assert!(!expected, "{from} -> {to} must succeed, got rejection");
                        assert_eq!(e.from, from);
                        assert_eq!(e.to, to);
                    }
                }
            }
        }
    }

    /// The documented linear lifecycle §8:
    /// INITIAL → HANDSHAKE → ESTABLISHED → REKEY → CLOSED
    /// plus the terminal short-circuits (Handshake → Closed, Established →
    /// Closed, Rekey → Closed) that the spec's diagram implies by making Closed
    /// reachable from every non-terminal state.
    #[test]
    fn every_documented_arc_is_allowed() {
        let mut s = ProtocolState::Initial;
        s = s.transition(ProtocolState::Handshake).unwrap();
        s = s.transition(ProtocolState::Established).unwrap();
        s = s.transition(ProtocolState::Rekey).unwrap();
        s = s.transition(ProtocolState::Closed).unwrap();
        assert_eq!(s, ProtocolState::Closed);

        // Short-circuits to Closed from every non-terminal, non-initial state
        // (Initial may only proceed to Handshake — the documented lifecycle
        // never goes directly from Initial to Closed).
        for from in [
            ProtocolState::Handshake,
            ProtocolState::Established,
            ProtocolState::Rekey,
        ] {
            assert!(
                from.can_transition_to(ProtocolState::Closed),
                "{from} -> Closed must be allowed (Closed is reachable from every non-initial state)"
            );
        }
    }

    #[test]
    fn closed_is_terminal() {
        assert!(ProtocolState::Closed.is_terminal());
        assert!(!ProtocolState::Initial.is_terminal());
        assert!(!ProtocolState::Handshake.is_terminal());
        assert!(!ProtocolState::Established.is_terminal());
        assert!(!ProtocolState::Rekey.is_terminal());
    }

    #[test]
    fn rekey_returns_to_established() {
        // §13: rekeying preserves communication continuity → Rekey → Established.
        assert!(ProtocolState::Rekey.can_transition_to(ProtocolState::Established));
        let s = ProtocolState::Established
            .transition(ProtocolState::Rekey)
            .unwrap()
            .transition(ProtocolState::Established)
            .unwrap();
        assert_eq!(s, ProtocolState::Established);
    }

    #[test]
    fn display_strings_are_stable() {
        // Explicit, stable strings (used in errors, metrics and logs).  Compare
        // against literals, not against `as_str`, so a change to either is
        // caught rather than agreeing with itself.
        assert_eq!(ProtocolState::Initial.to_string(), "initial");
        assert_eq!(ProtocolState::Handshake.to_string(), "handshake");
        assert_eq!(ProtocolState::Established.to_string(), "established");
        assert_eq!(ProtocolState::Rekey.to_string(), "rekey");
        assert_eq!(ProtocolState::Closed.to_string(), "closed");
    }

    #[test]
    fn error_display_is_explicit() {
        let e = ProtocolState::Initial
            .transition(ProtocolState::Established)
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "invalid state transition: initial -> established"
        );
    }
}
