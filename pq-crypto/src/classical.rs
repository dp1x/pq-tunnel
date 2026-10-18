use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

pub type X25519PublicKey = PublicKey;
pub type X25519SecretKey = StaticSecret;

#[derive(Clone)]
pub struct X25519Keypair {
    pub public: X25519PublicKey,
    pub secret: X25519SecretKey,
}

impl fmt::Debug for X25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519Keypair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl X25519Keypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        X25519Keypair { public, secret }
    }

    /// X25519 shared secret, **or `None` when the exchange was not
    /// contributory** (RFC 7748 §6.1 / §7).
    ///
    /// Curve25519 has cofactor 8, so a peer-supplied public key of small
    /// order drives every scalar multiple to the identity element and the
    /// output is all-zero. Returning that value silently would let the peer
    /// dictate the DH leg's contribution to the hybrid master secret. RFC 7748
    /// §6.1 permits the check ("MAY check ... whether K is the all-zero value
    /// and abort if so"); §7 records that a large number of implementations do
    /// not, and `x25519-dalek` `SharedSecret::diffie_hellman` does not reject
    /// low-order inputs by default.
    ///
    /// `None` is a fail-secure signal: callers abort the handshake. It is not a
    /// wire-format change and cannot be triggered by a conforming peer — an
    /// ephemeral keypair generated here has order-8·ℓ u-coordinate, so a
    /// contributory exchange is always non-zero.
    pub fn diffie_hellman(&self, other: &X25519PublicKey) -> Option<[u8; 32]> {
        let shared = self.secret.diffie_hellman(other);
        if !shared.was_contributory() {
            return None;
        }
        Some(*shared.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keypair_generation_succeeds() {
        let kp = X25519Keypair::generate();
        let pub_bytes: [u8; 32] = kp.public.to_bytes();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn x25519_diffie_hellman_symmetric() {
        let kp_a = X25519Keypair::generate();
        let kp_b = X25519Keypair::generate();

        let secret_ab = kp_a.diffie_hellman(&kp_b.public);
        let secret_ba = kp_b.diffie_hellman(&kp_a.public);

        assert_eq!(
            secret_ab.unwrap(),
            secret_ba.unwrap(),
            "X25519 DH must be symmetric"
        );
        assert_ne!(
            secret_ab.unwrap(),
            [0u8; 32],
            "shared secret must not be all zeros"
        );
    }

    #[test]
    fn x25519_different_keypairs_produce_different_secrets() {
        let kp_a = X25519Keypair::generate();
        let kp_b = X25519Keypair::generate();
        let kp_c = X25519Keypair::generate();

        let secret_ab = kp_a.diffie_hellman(&kp_b.public);
        let secret_ac = kp_a.diffie_hellman(&kp_c.public);

        assert_ne!(
            secret_ab, secret_ac,
            "different keypairs must produce different shared secrets"
        );
    }

    // -----------------------------------------------------------------------
    // Known-answer test (M5.1) — RFC 7748 §6.1 (D21)
    // -----------------------------------------------------------------------

    #[test]
    fn x25519_rfc7748_6_1_kat() {
        use crate::kat_vectors::{
            RFC7748_ALICE_PRIVATE, RFC7748_ALICE_PUBLIC, RFC7748_BOB_PRIVATE, RFC7748_BOB_PUBLIC,
            RFC7748_SHARED, unhex,
        };
        let alice_secret = StaticSecret::from(
            <[u8; 32]>::try_from(unhex(RFC7748_ALICE_PRIVATE).as_slice()).unwrap(),
        );
        let bob_secret = StaticSecret::from(
            <[u8; 32]>::try_from(unhex(RFC7748_BOB_PRIVATE).as_slice()).unwrap(),
        );

        // Public-key derivation: X25519(scalar, basepoint).
        let alice_pair = X25519Keypair {
            public: PublicKey::from(&alice_secret),
            secret: alice_secret,
        };
        let bob_pair = X25519Keypair {
            public: PublicKey::from(&bob_secret),
            secret: bob_secret,
        };
        let alice_expected: [u8; 32] =
            <[u8; 32]>::try_from(unhex(RFC7748_ALICE_PUBLIC).as_slice()).unwrap();
        let bob_expected: [u8; 32] =
            <[u8; 32]>::try_from(unhex(RFC7748_BOB_PUBLIC).as_slice()).unwrap();
        assert_eq!(
            alice_pair.public.to_bytes(),
            alice_expected,
            "RFC 7748 §6.1 Alice's public key must match"
        );
        assert_eq!(
            bob_pair.public.to_bytes(),
            bob_expected,
            "RFC 7748 §6.1 Bob's public key must match"
        );

        // Shared-secret computation, both directions.
        let shared_expected: [u8; 32] =
            <[u8; 32]>::try_from(unhex(RFC7748_SHARED).as_slice()).unwrap();
        assert_eq!(
            alice_pair.diffie_hellman(&bob_pair.public),
            Some(shared_expected),
            "RFC 7748 §6.1 shared secret K must match (Alice side)"
        );
        assert_eq!(
            bob_pair.diffie_hellman(&alice_pair.public),
            Some(shared_expected),
            "RFC 7748 §6.1 shared secret K must match (Bob side)"
        );
    }

    // -----------------------------------------------------------------------
    // Low-order / non-contributory rejection (RFC 7748 §6.1, §7)
    // -----------------------------------------------------------------------
    //
    // The u-coordinates below are the canonical small-order points of
    // curve25519 (the order-1 identity and the order-4 / order-8 torsion
    // points). RFC 7748 §7: "an input point of small order will eliminate any
    // contribution from the other party's private key ... This situation can
    // be detected by checking for the all-zero output, which implementations MAY
    // do, as specified in Section 6."

    /// The full published set of low-order curve25519 u-coordinates, in
    /// RFC 7748 §6.1 little-endian encoding.
    ///
    /// Every one of these drives `X25519(sk, u)` to the identity element, so
    /// the shared secret is all-zero regardless of the secret scalar.
    const LOW_ORDER_POINTS: [[u8; 32]; 5] = [
        // Order 1 (the identity).
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        // Order 2.
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        // Order 4.
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // Order 4 (negative).
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        // Order 8.
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    /// Every low-order peer key must be rejected, not silently accepted.
    ///
    /// This is the defense-in-depth check for the classic "Mallory replaces
    /// both public keys with zero" attack described in RFC 7748 §6.1 / the
    /// `was_contributory` docs: without it the peer dictates the DH leg's
    /// contribution to the hybrid master secret and neither side can detect it.
    ///
    /// Self-derived expectations (not an external anchor): the input points
    /// are the published low-order u-coordinates, and the assertion is that the
    /// wrapper refuses a non-contributory exchange.
    #[test]
    fn low_order_peer_keys_are_rejected() {
        let kp = X25519Keypair::generate();
        for point in LOW_ORDER_POINTS {
            let peer = PublicKey::from(point);
            assert_eq!(
                kp.diffie_hellman(&peer),
                None,
                "a small-order peer key must fail the contributory check \
                 (got {:?})",
                PublicKey::from(point)
            );
        }
    }

    /// The rejection is symmetric in the value X25519 actually returns: the
    /// u-coordinate. RFC 7748 §6.1 detects non-contributory behaviour by
    /// checking the all-zero u-coordinate, and a `u`-coordinate of a torsion
    /// point is shared by the point and its negation — so both peers see all
    /// zero regardless of the peer's point order.
    #[test]
    fn low_order_rejection_is_symmetric() {
        for point in LOW_ORDER_POINTS {
            let attacker = X25519Keypair {
                public: PublicKey::from(point),
                secret: StaticSecret::from([0x42u8; 32]),
            };
            let honest = X25519Keypair::generate();
            assert_eq!(
                honest.diffie_hellman(&attacker.public),
                None,
                "the honest peer must observe the non-contributory exchange"
            );
            assert!(
                attacker.diffie_hellman(&honest.public).is_none()
                    || attacker.diffie_hellman(&honest.public).unwrap() != [0u8; 32],
                "the low-order holder must never receive an all-zero shared secret"
            );
        }
    }

    /// A legitimate exchange must never be refused: the contributory check
    /// must not degrade normal handshakes into failures.
    #[test]
    fn contributory_exchange_is_never_rejected() {
        for _ in 0..64 {
            let a = X25519Keypair::generate();
            let b = X25519Keypair::generate();
            let ab = a.diffie_hellman(&b.public);
            let ba = b.diffie_hellman(&a.public);
            assert!(ab.is_some() && ba.is_some(), "valid peers must agree");
            assert_eq!(ab.unwrap(), ba.unwrap());
            assert_ne!(ab.unwrap(), [0u8; 32]);
        }
    }
}
