use std::sync::Arc;

use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
use rustls::{ServerConfig as RustlsServerConfig, pki_types::{CertificateDer, PrivateKeyDer}};

use crate::config::TunnelConfig;
use crate::error::TunnelError;

pub async fn listen(config: TunnelConfig) -> Result<crate::session::Listener, TunnelError> {
    let listen_addr = config.listen_addr.ok_or(TunnelError::InvalidConfig(
        "listen address required".into(),
    ))?;

    let (cert_der, key_der) = generate_cert()?;

    let tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| TunnelError::Tls(format!("rustls server err: {:?}", e)))?;

    let quic_config = QuicServerConfig::try_from(tls_config)
        .map_err(|e| TunnelError::Tls(format!("quic server err: {:?}", e)))?;

    let endpoint = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(quic_config)),
        listen_addr,
    )
    .map_err(|e| TunnelError::Quic(format!("listen err: {}", e)))?;

    Ok(crate::session::Listener {
        config,
        endpoint: Some(endpoint),
    })
}

pub async fn accept_and_handshake(
    listener: &mut crate::session::Listener,
) -> Result<crate::session::Session, TunnelError> {
    let endpoint = listener.endpoint.as_ref()
        .ok_or(TunnelError::InvalidConfig("listener not bound".into()))?;

    tracing::debug!("Accepting connection...");
    let connecting = endpoint.accept().await
        .ok_or(TunnelError::ConnectionClosed)?;
    tracing::debug!("Connection accepted, awaiting handshake...");

    let conn = connecting.await
        .map_err(|e| TunnelError::Quic(format!("accept err: {}", e)))?;
    tracing::debug!("QUIC connection established, opening stream...");

    let (mut send, mut recv) = conn.accept_bi().await
        .map_err(|e| TunnelError::Quic(format!("accept_bi: {}", e)))?;
    tracing::debug!("Stream open, running PQ handshake...");

    let handshake_result = crate::handshake::server_handshake(
        &listener.config.identity,
        &mut send,
        &mut recv,
    ).await.map_err(|e| TunnelError::Quic(format!("handshake: {}", e)))?;

    tracing::debug!("Handshake complete! session_id={:02x?}", &handshake_result.session_id[..4]);

    let _ = send.finish();

    let mut config = listener.config.clone();
    config.identity = listener.config.identity.clone();

    Ok(crate::session::Session::new(
        config,
        conn,
        handshake_result.shared_secret,
        handshake_result.handshake_duration_ms,
    ))
}

fn generate_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TunnelError> {
    let cert = rcgen::Certificate::from_params(
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]),
    )
    .map_err(|e| TunnelError::Tls(format!("cert gen err: {:?}", e)))?;

    let cert_der = CertificateDer::from(
        cert.serialize_der()
            .map_err(|e| TunnelError::Tls(format!("cert der err: {:?}", e)))?,
    );

    let key_der = PrivateKeyDer::try_from(cert.serialize_private_key_der())
        .map_err(|e| TunnelError::Tls(format!("key der err: {:?}", e)))?;

    Ok((cert_der, key_der))
}
