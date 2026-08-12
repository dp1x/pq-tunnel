//! Raw UDP transport carrying fixed-size `WirePacket` datagrams.
//!
//! PROTOCOL_SPEC §7.5 makes Tunnel transport-agnostic: it SHOULD NOT depend on
//! fixed network paths, permanent IP addresses, or specific MTU sizes.
//! IMPLEMENTATION_GUIDE §3.6 requires the transport module to avoid those
//! assumptions.  A raw UDP socket carrying exactly one [`WirePacket`] per
//! datagram satisfies both: the wire framing is defined entirely by the codec
//! (fixed `PACKET_SIZE`), and UDP itself is a datagram service with no path or
//! address permanence assumptions.
//!
//! The peer is an explicit field (not derived from the last received source)
//! so the caller — a session manager — decides how packets are associated with
//! connections.  `set_peer` supports roaming/NAT without rebinding
//! (PROTOCOL_SPEC §10: sessions must not depend permanently on source
//! addresses).
//!
//! # Security notes
//!
//! - Every datagram MUST be exactly `PACKET_SIZE` bytes.  A receive buffer of
//!   `PACKET_SIZE + 1` detects oversized datagrams (UDP truncates silently into
//!   a smaller buffer, which would otherwise be indistinguishable from a
//!   legitimate fixed-size packet); both oversize and undersize are rejected as
//!   [`UdpError::WrongSize`].  Callers then feed the packet to the AEAD envelope,
//!   which performs the real authenticity check (PROTOCOL_SPEC §14).
//! - This module performs no authentication.  Authentication lives in the
//!   envelope/handshake layers; UDP here only guarantees datagram boundaries.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::codec::{PACKET_SIZE, WirePacket};

/// Transport-level failures.  These are distinct from protocol-level rejections
/// ([`crate::CodecError`]): an `UdpError` means the datagram could not even be
/// formed into a `WirePacket` (wrong size) or the socket failed.
#[derive(Debug, thiserror::Error)]
pub enum UdpError {
    /// Underlying socket error.
    #[error("udp io: {0}")]
    Io(#[from] io::Error),

    /// `send` was called with no peer configured.
    #[error("no remote peer configured")]
    NoPeer,

    /// A received datagram was not exactly `PACKET_SIZE` bytes.
    #[error("datagram size mismatch: expected {expected}, got {got}")]
    WrongSize { expected: usize, got: usize },
}

impl UdpError {
    /// Whether this is the *recoverable* peer-reset signal: an ICMP
    /// port-unreachable (Windows WSAECONNRESET) or connection-refused
    /// surfacing on the socket.  In UDP this is informational — the peer
    /// (or its port) is gone — not a protocol failure.  It must not be
    /// treated as fatal: one vanished peer must never terminate a
    /// multi-session server (M9B).
    pub fn is_recoverable_reset(&self) -> bool {
        matches!(
            self,
            UdpError::Io(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                )
        )
    }
}

/// A raw UDP endpoint carrying exactly one [`WirePacket`] per datagram.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
    peer: Option<SocketAddr>,
}

impl UdpTransport {
    /// Bind a listening socket (server role).  Callers typically follow up with
    /// [`Self::set_peer`] once a source is selected.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
            peer: None,
        })
    }

    /// Bind an ephemeral socket and set the remote peer (client role).
    ///
    /// The socket is deliberately left *unconnected*: a kernel-connected UDP
    /// socket pins the local kernel to one remote address, so updating
    /// [`Self::set_peer`] (roaming / NAT, §10) would silently stop working —
    /// the kernel filters incoming datagrams to the originally-connected peer
    /// only.  All sends go through [`Self::send_to`] with the explicit peer
    /// field instead, so the peer can change at any time.
    pub async fn connect(remote: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        Ok(Self {
            socket,
            peer: Some(remote),
        })
    }

    /// Local address this endpoint is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The current remote peer, if any.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Update the remote peer without rebinding (roaming / NAT; §10).
    ///
    /// Because the socket is never kernel-connected, the new peer takes effect
    /// immediately for both send and receive.
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    /// Send one fixed-size packet to the configured peer.
    ///
    /// Fails with [`UdpError::NoPeer`] if no peer has been set.  The socket is
    /// never kernel-connected, so this works for both the client role (peer set
    /// via [`Self::connect`]) and the server role (peer set via
    /// [`Self::set_peer`]), and the destination always follows the current
    /// `peer` field — roaming changes take effect immediately.
    pub async fn send(&self, packet: &WirePacket) -> Result<(), UdpError> {
        let peer = self.peer.ok_or(UdpError::NoPeer)?;
        self.send_to(packet, peer).await
    }

    /// Send one fixed-size packet to a specific peer (server role reply).
    pub async fn send_to(&self, packet: &WirePacket, peer: SocketAddr) -> Result<(), UdpError> {
        let n = self.socket.send_to(packet.as_bytes(), peer).await?;
        if n != PACKET_SIZE {
            // UDP send_to returns the number of bytes written; a short write of a
            // single fixed-size buffer should be impossible, but do not accept a
            // truncated datagram as if it were a full packet.
            return Err(UdpError::WrongSize {
                expected: PACKET_SIZE,
                got: n,
            });
        }
        Ok(())
    }

    /// Receive one fixed-size packet plus its source address.
    ///
    /// Rejects any datagram whose length is not exactly `PACKET_SIZE` bytes
    /// (oversize or undersize), returning [`UdpError::WrongSize`].  The source
    /// address is returned so a server-side session manager can perform
    /// source-address binding at its own layer (§10 note: sessions must not
    /// *depend permanently* on source addresses; binding is a lookup hint only).
    pub async fn recv(&self) -> Result<(WirePacket, SocketAddr), UdpError> {
        // One extra byte lets us detect oversized datagrams: UDP truncates into
        // a too-small buffer, which would otherwise look like a valid 1280-byte
        // packet.  With PACKET_SIZE+1, a larger datagram either yields
        // n == PACKET_SIZE+1 (Linux truncation) or fails with WSAEMSGSIZE on
        // Windows; both are rejected below.
        let mut buf = [0u8; PACKET_SIZE + 1];
        let (n, from) = match self.socket.recv_from(&mut buf).await {
            Ok(v) => v,
            // Windows: a datagram larger than the receive buffer fails with
            // WSAEMSGSIZE (10040) rather than truncating.  Normalize that into
            // the same WrongSize rejection used on other platforms.
            Err(e) if e.raw_os_error() == Some(10040) => {
                return Err(UdpError::WrongSize {
                    expected: PACKET_SIZE,
                    got: PACKET_SIZE + 1, // at least this large
                });
            }
            Err(e) => return Err(UdpError::Io(e)),
        };
        if n != PACKET_SIZE {
            return Err(UdpError::WrongSize {
                expected: PACKET_SIZE,
                got: n,
            });
        }
        let packet = WirePacket::from_bytes(&buf[..PACKET_SIZE])
            .expect("exactly PACKET_SIZE bytes always parses (codec invariant)");
        Ok((packet, from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{PACKET_NONCE_LEN, SESSION_ID_LEN};

    fn test_packet() -> WirePacket {
        let sid = [0xAA; SESSION_ID_LEN];
        let nonce: [u8; PACKET_NONCE_LEN] = [0; PACKET_NONCE_LEN];
        let hdr = crate::codec::PacketHeader::new(sid, u64::from_be_bytes(nonce));
        WirePacket::from_parts(
            &hdr.encode(),
            &[0x42; PACKET_SIZE - crate::codec::HEADER_LEN],
        )
        .expect("fixed-size region")
    }

    async fn pair() -> (UdpTransport, UdpTransport) {
        let mut server = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpTransport::connect(server_addr).await.unwrap();
        server.set_peer(client.local_addr().unwrap());
        (client, server)
    }

    #[tokio::test]
    async fn roundtrip_send_recv() {
        let (client, server) = pair().await;
        let pkt = test_packet();

        client.send(&pkt).await.expect("client send");
        let (got, from) = server.recv().await.expect("server recv");
        // The client binds to a wildcard address, so its reported local IP is
        // `0.0.0.0` while the kernel selects a loopback source for the actual
        // send.  Compare the port (and that the source is loopback), which is
        // what identifies the endpoint here.
        assert_eq!(from.port(), client.local_addr().unwrap().port());
        assert!(from.ip().is_loopback(), "source must be loopback");
        assert_eq!(got.as_bytes(), pkt.as_bytes());
    }

    #[tokio::test]
    async fn send_without_peer_fails() {
        let server = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let err = server.send(&test_packet()).await.unwrap_err();
        assert!(
            matches!(err, UdpError::NoPeer),
            "expected NoPeer, got {err}"
        );
    }

    #[tokio::test]
    async fn undersized_datagram_rejected() {
        let (client, server) = pair().await;
        // Send a 5-byte datagram directly through the socket.
        client
            .socket
            .send_to(&[0u8; 5], server.local_addr().unwrap())
            .await
            .unwrap();
        let err = server.recv().await.unwrap_err();
        match err {
            UdpError::WrongSize { expected, got } => {
                assert_eq!(expected, PACKET_SIZE);
                assert_eq!(got, 5);
            }
            other => panic!("expected WrongSize, got {other}"),
        }
    }

    #[tokio::test]
    async fn oversized_datagram_rejected() {
        let (client, server) = pair().await;
        // Larger than PACKET_SIZE+1 buffer → truncated to PACKET_SIZE+1, rejected.
        client
            .socket
            .send_to(&[0u8; PACKET_SIZE + 5], server.local_addr().unwrap())
            .await
            .unwrap();
        let err = server.recv().await.unwrap_err();
        assert!(
            matches!(err, UdpError::WrongSize { got, .. } if got != PACKET_SIZE),
            "oversized datagram must be rejected, got {err}"
        );
    }

    #[tokio::test]
    async fn send_to_works_without_peer() {
        let client = UdpTransport::connect("127.0.0.1:9".parse().unwrap())
            .await
            .unwrap();
        let server = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        // server has no peer but can still receive via send_to path.
        client
            .socket
            .send_to(&[0u8; PACKET_SIZE], server_addr)
            .await
            .unwrap();
        let (got, from) = server.recv().await.expect("recv");
        assert_eq!(got.as_bytes().len(), PACKET_SIZE);
        assert_eq!(from.port(), client.local_addr().unwrap().port());
        assert!(from.ip().is_loopback(), "source must be loopback");
    }

    #[tokio::test]
    async fn set_peer_supports_rebinding() {
        let mut server = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr2 = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        server.set_peer(addr2);
        assert_eq!(server.peer(), Some(addr2));
    }

    #[test]
    fn recoverable_reset_classification() {
        // M9B: ICMP port-unreachable (Windows WSAECONNRESET) and
        // connection-refused are informational UDP signals — recoverable;
        // anything else (or a non-Io error) is not.
        assert!(
            UdpError::Io(io::Error::new(io::ErrorKind::ConnectionReset, "reset"))
                .is_recoverable_reset()
        );
        assert!(
            UdpError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
                .is_recoverable_reset()
        );
        assert!(
            !UdpError::Io(io::Error::new(io::ErrorKind::WouldBlock, "block"))
                .is_recoverable_reset()
        );
        assert!(
            !UdpError::WrongSize {
                expected: 1,
                got: 2
            }
            .is_recoverable_reset()
        );
        assert!(!UdpError::NoPeer.is_recoverable_reset());
    }

    #[tokio::test]
    async fn roaming_reroutes_to_new_peer() {
        // §10 roaming: an unconnected socket lets `set_peer` reroute traffic to
        // a new address immediately.  (With a kernel-connected socket this would
        // silently break — the kernel would keep filtering to the old peer.)
        let server_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr_a = server_a.local_addr().unwrap();
        let mut client = UdpTransport::connect(addr_a).await.unwrap();

        // Original peer receives the first send.
        client.send(&test_packet()).await.unwrap();
        let (_pkt, from_a) = server_a.recv().await.unwrap();
        assert_eq!(from_a.port(), client.local_addr().unwrap().port());
        assert!(from_a.ip().is_loopback(), "source must be loopback");

        // Roam to a second endpoint; sends must now arrive there.
        let server_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr_b = server_b.local_addr().unwrap();
        client.set_peer(addr_b);
        client.send(&test_packet()).await.unwrap();
        let (_pkt, from_b) = server_b.recv().await.unwrap();
        assert_eq!(from_b.port(), client.local_addr().unwrap().port());
        assert!(from_b.ip().is_loopback(), "source must be loopback");
    }
}
