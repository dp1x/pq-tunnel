use std::sync::Arc;

use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::{ClientConfig as RustlsClientConfig, pki_types::CertificateDer};

use crate::config::TunnelConfig;
use crate::error::TunnelError;

pub async fn connect(config: TunnelConfig) -> Result<crate::session::Session, TunnelError> {
    let remote = config
        .remote_addr
        .ok_or(TunnelError::InvalidConfig("remote address required".into()))?;

    let tls_config = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let quic_config = QuicClientConfig::try_from(tls_config)
        .map_err(|e| TunnelError::Tls(format!("quic tls: {:?}", e)))?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))
        .map_err(|e| TunnelError::Quic(format!("endpoint: {}", e)))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic_config)));

    tracing::info!("Connecting to {}...", remote);
    let conn = endpoint
        .connect(remote, "pq-tunnel")
        .map_err(|e| TunnelError::Quic(format!("connect: {}", e)))?;
    tracing::info!("QUIC connection established, waiting for handshake...");

    let quic_conn = conn
        .await
        .map_err(|e| TunnelError::Quic(format!("connecting: {}", e)))?;
    tracing::info!("QUIC handshake complete, opening bidirectional stream...");

    let (mut send, mut recv) = quic_conn
        .open_bi()
        .await
        .map_err(|e| TunnelError::Quic(format!("open_bi: {}", e)))?;

    let handshake_result =
        crate::handshake::client_handshake(&config.identity, &mut send, &mut recv)
            .await
            .map_err(|e| TunnelError::Quic(format!("handshake: {}", e)))?;

    Ok(crate::session::Session::new_with_streams(
        config,
        quic_conn.clone(),
        send,
        recv,
        handshake_result.shared_secret,
        handshake_result.handshake_duration_ms,
    ))
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
