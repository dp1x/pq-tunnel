pub mod client;
pub mod codec;
pub mod config;
pub mod envelope;
pub mod error;
pub mod handshake;
mod handshake_v2;
pub use handshake_v2::{
    ClientConfig as HandshakeV2ClientConfig, ClientConfirm, ClientEvent, ClientHandshake,
    ClientHello, FINISHED_MAC_LEN, FragmentAssembler, FragmentResult, HS_FRAG_BODY_MAX,
    HS_FRAG_HEADER_LEN, HS_TYPE_CLIENT_CONFIRM, HS_TYPE_CLIENT_HELLO, HS_TYPE_SERVER_HELLO,
    HandshakeFragment, HandshakeOutcome, HandshakeTransport, HandshakeV2Error, M1_BODY_LEN,
    M1_FRAG_COUNT, M2_BODY_LEN, M2_FRAG_COUNT, M3_BODY_LEN, M3_FRAG_COUNT,
    ServerConfig as HandshakeV2ServerConfig, ServerEvent, ServerHandshake, ServerHello,
    X25519_PUBLIC_KEY_BYTES, client_handshake_v2, expected_frag_count, fragment_message,
    is_handshake_fragment, message_body_len, server_handshake_v2, th1_from_m1, th2_from_m1_m2,
    th3_from_m1_m2_m3,
};
pub mod metrics;
pub mod nonce;
pub mod replay;
pub mod server;
pub mod session;
mod session_manager;
pub mod state;
pub mod udp;
pub mod wire_session;

pub use session_manager::{
    ClientManagerState, ClientSessionManager, CloseReason, ManagerError, ManagerEvent,
    ManagerNotification, ServerAppCommand, ServerSessionManager, SessionLimits, run_client_manager,
    run_server_manager,
};

pub use client::connect;
pub use codec::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, Direction, HEADER_LEN, INNER_PLAINTEXT_LEN, InnerPlaintext,
    MessageType, PACKET_NONCE_LEN, PACKET_SIZE, PAYLOAD_LEN, PROTOCOL_VERSION, PacketHeader,
    SESSION_ID_LEN, WirePacket,
};
pub use config::TunnelConfig;
pub use envelope::{CipherSession, Role};
pub use error::CodecError;
pub use error::TunnelError;
pub use handshake::{HandshakeError, HandshakeResult, client_handshake, server_handshake};
pub use metrics::SessionMetrics;
pub use server::listen;
pub use session::{Listener, Session};
pub use state::{InvalidTransition, ProtocolState};
pub use udp::{UdpError, UdpTransport};
pub use wire_session::{SessionError, WireSession};
