use anyhow::{Context, Result};
use ironrdp::connector;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageOutput};
use ironrdp_connector::sspi::network_client::NetworkClient;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use std::net::TcpStream;
use std::sync::{Arc, mpsc};
use std::time::Duration;
use x509_cert::der::Decode;

use crate::config::Config;
use crate::rdp_parser::RdpFile;
use crate::sia::GatewayConnection;

use crate::sia::GatewayStream;

/// Holds the active RDP session state
#[allow(dead_code)]
pub struct RdpSession {
    pub framed: RdpFramed,
    pub active_stage: ActiveStage,
    pub desktop_size: DesktopSize,
}

/// Type alias for the framed connection (either direct TLS or via Gateway)
#[allow(dead_code, clippy::large_enum_variant)]
pub enum RdpFramed {
    Direct(ironrdp_blocking::Framed<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    Gateway(ironrdp_blocking::Framed<GatewayStream>),
}

#[derive(Debug, Clone, Copy)]
pub struct DesktopSize {
    pub width: u16,
    pub height: u16,
}

/// Framebuffer update received from the server
#[allow(dead_code)]
pub struct FrameUpdate {
    /// RGBA pixel data
    pub data: Vec<u8>,
    pub width: u16,
    pub height: u16,
}

/// Input events from window to RDP thread
#[derive(Debug)]
pub enum InputEvent {
    Mouse(FastPathInputEvent),
    Keyboard(FastPathInputEvent),
    Shutdown,
}

/// Build the IronRDP connector config from our parsed RDP file
fn build_connector_config(
    rdp_file: &RdpFile,
    config: &Config,
    username: &str,
    password: &str,
) -> connector::Config {
    // Use config resolution (user preference) instead of RDP file
    let width = config.default_width;
    let height = config.default_height;

    // PSM uses non-standard format "domain\user@uuid" which IronRDP's sspi library
    // doesn't support (rejects @ in username when domain is provided).
    //
    // Workaround: Pass the full "domain\user@uuid" as username with NO domain,
    // let IronRDP parse it. The sspi::Username::parse() will split on \ and create
    // a DownLevelLogonName, but will fail if account_name contains @.
    //
    // Alternative: Use full username as-is and rely on server-side parsing
    let domain_opt = rdp_file.domain().map(|s| s.to_string());

    // Check if CredSSP/NLA should be enabled (default to true if not specified)
    let enable_credssp = rdp_file.enable_credssp().unwrap_or(true);

    // Get alternate shell (used by CyberArk for PSM token)
    let alternate_shell = rdp_file.alternate_shell().unwrap_or_default().to_string();

    tracing::info!(
        "Using credentials: username='{}', domain={:?}, enable_credssp={}, alternate_shell='{}'",
        username,
        domain_opt,
        enable_credssp,
        alternate_shell
    );

    connector::Config {
        credentials: connector::Credentials::UsernamePassword {
            username: username.to_string(),
            password: password.to_string(),
        },
        domain: None, // Don't provide domain, let username parsing handle it
        enable_tls: true,
        enable_credssp,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0, // auto-detect
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize { width, height },
        desktop_scale_factor: 0,
        bitmap: None,
        client_build: 0,
        client_name: "cyberark-rdp".to_string(),
        client_dir: String::new(),
        alternate_shell: alternate_shell.clone(),
        work_dir: String::new(),
        platform: MajorPlatformType::MACINTOSH,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: true,
        performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
        license_cache: None,
        timezone_info: ironrdp_pdu::rdp::client_info::TimezoneInfo::default(),
        enable_server_pointer: true,
        pointer_software_rendering: false,
    }
}

/// Build a TLS config (with optional cert ignore)
fn build_tls_config(cert_ignore: bool) -> Result<rustls::ClientConfig> {
    let mut config = if cert_ignore {
        // Skip certificate verification (like /cert:ignore)
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        let cert_result = rustls_native_certs::load_native_certs();

        // Log any errors but still use certificates that loaded successfully
        for error in &cert_result.errors {
            tracing::warn!("Error loading native cert: {:?}", error);
        }

        // Add all successfully loaded certificates
        for cert in cert_result.certs {
            root_store.add(cert).ok();
        }

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // CredSSP does not support TLS session resumption
    config.resumption = rustls::client::Resumption::disabled();

    Ok(config)
}

/// Dummy certificate verifier that accepts everything
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Stub NetworkClient for basic CredSSP (no Kerberos)
/// Only username/password authentication is supported, no external network requests needed
#[derive(Debug, Clone)]
struct StubNetworkClient;

impl NetworkClient for StubNetworkClient {
    fn send(
        &self,
        _request: &ironrdp_connector::sspi::generator::NetworkRequest,
    ) -> ironrdp_connector::sspi::Result<Vec<u8>> {
        // For basic username/password CredSSP, no external network requests are needed
        // This would only be called for Kerberos authentication
        Err(ironrdp_connector::sspi::Error::new(
            ironrdp_connector::sspi::ErrorKind::UnsupportedFunction,
            "Network requests not supported (Kerberos not configured)",
        ))
    }
}

/// Extract server public key from TLS connection
fn extract_server_public_key(
    tls_stream: &rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
) -> Result<Vec<u8>> {
    let peer_certs = tls_stream
        .conn
        .peer_certificates()
        .context("no peer certificates")?;

    let server_cert_der = peer_certs.first().context("no server certificate")?;

    // Parse DER-encoded certificate to x509_cert::Certificate
    let server_cert = x509_cert::Certificate::from_der(server_cert_der.as_ref())
        .context("failed to parse server certificate")?;

    let public_key = ironrdp_tls::extract_tls_server_public_key(&server_cert)
        .context("failed to extract public key")?;

    Ok(public_key.to_vec())
}

/// Establish an RDP connection via Gateway
fn connect_via_gateway(
    rdp_file: &RdpFile,
    config: &Config,
    username: &str,
    password: &str,
) -> Result<RdpSession> {
    tracing::info!("Connecting via RDP Gateway");

    let hostname = rdp_file.hostname().context("no hostname in RDP file")?;
    let port = rdp_file.port();

    let gateway_hostname = rdp_file
        .gateway_hostname()
        .context("gateway configured but no gateway hostname")?;

    // Extract SSO token from alternate shell (CyberArk SIA uses this)
    let sso_token = rdp_file
        .sso_token()
        .or_else(|| rdp_file.gateway_access_token())
        .context("gateway configured but no SSO token or access token found")?;

    tracing::debug!("Using PAA cookie for gateway authentication");

    // Create gateway connection
    let gateway = GatewayConnection::new(
        gateway_hostname,
        hostname.to_string(),
        port,
        sso_token.to_string(),
        password.to_string(),
    )?;

    // Connect through gateway - this returns a WebSocket stream
    // The gateway will tunnel our RDP traffic to the target server
    let gateway_stream = gateway.connect()?;

    tracing::info!("Gateway WebSocket tunnel established, starting RDP handshake");

    // Now use the gateway stream as our base connection
    let client_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));

    // Build connector config
    let connector_config = build_connector_config(rdp_file, config, username, password);
    let mut framed = ironrdp_blocking::Framed::new(gateway_stream);
    let mut connector = connector::ClientConnector::new(connector_config, client_addr);

    // Begin RDP negotiation through the gateway tunnel
    tracing::info!("Starting RDP negotiation through gateway...");
    let should_upgrade = ironrdp_blocking::connect_begin(&mut framed, &mut connector)
        .context("RDP connect_begin failed through gateway")?;

    // For gateway connections, the WebSocket already provides encryption
    // Mark as upgraded but don't actually do TLS upgrade
    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);

    // Create stub network client (no Kerberos support)
    let mut network_client = StubNetworkClient;

    // For gateway, we use empty server public key (encryption is handled by WebSocket/TLS)
    let server_name = connector::ServerName::new(hostname.to_string());

    tracing::info!("CredSSP/NLA authentication through gateway...");

    let connection_result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector, // Now owned, not &mut
        &mut framed,
        &mut network_client,
        server_name,
        vec![], // Empty server public key for gateway
        None,   // No kerberos config
    )
    .context("RDP connect_finalize failed through gateway")?;

    // Use config resolution (user preference) instead of RDP file
    let width = config.default_width;
    let height = config.default_height;

    tracing::info!("Connected via Gateway! Desktop: {}x{}", width, height);

    let active_stage = ActiveStage::new(connection_result);

    Ok(RdpSession {
        framed: RdpFramed::Gateway(framed),
        active_stage,
        desktop_size: DesktopSize { width, height },
    })
}

/// Establish an RDP connection
///
/// This follows the IronRDP blocking example pattern:
/// 1. TCP connect
/// 2. RDP negotiation (connect_begin)
/// 3. TLS upgrade
/// 4. CredSSP/NLA authentication (connect_finalize)
/// 5. Return active session
pub fn connect(
    rdp_file: &RdpFile,
    config: &Config,
    username: &str,
    password: &str,
) -> Result<RdpSession> {
    let hostname = rdp_file.hostname().context("no hostname in RDP file")?;
    let port = rdp_file.port();
    let addr = format!("{}:{}", hostname, port);

    // 1. Establish base connection (direct TCP or via Gateway)
    let use_gateway = rdp_file.gateway_usage();

    if use_gateway {
        return connect_via_gateway(rdp_file, config, username, password);
    }

    tracing::info!("Connecting directly to {}...", addr);

    // Direct TCP connection
    let tcp_stream =
        TcpStream::connect(&addr).with_context(|| format!("failed to connect to {}", addr))?;

    tcp_stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .context("set_read_timeout")?;

    let client_addr = tcp_stream.local_addr().context("get local address")?;

    // 2. Build connector config
    let connector_config = build_connector_config(rdp_file, config, username, password);

    // Create owned String for 'static lifetime
    let hostname_owned = hostname.to_string();
    let rustls_server_name: rustls::pki_types::ServerName<'static> =
        rustls::pki_types::ServerName::try_from(hostname_owned.clone()).unwrap_or_else(|_| {
            rustls::pki_types::ServerName::IpAddress(
                addr.parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
                    .into(),
            )
        });

    // Create IronRDP ServerName for connect_finalize
    let server_name = connector::ServerName::new(hostname_owned);

    let mut framed = ironrdp_blocking::Framed::new(tcp_stream);
    let mut connector = connector::ClientConnector::new(connector_config, client_addr);

    // 3. Begin RDP negotiation
    tracing::info!("Starting RDP negotiation...");
    let should_upgrade = ironrdp_blocking::connect_begin(&mut framed, &mut connector)
        .context("RDP connect_begin failed")?;

    // 4. TLS upgrade
    tracing::info!("TLS upgrade...");
    let initial_stream = framed.into_inner_no_leftover();
    let tls_config = build_tls_config(config.cert_ignore)?;
    let tls_connector =
        rustls::ClientConnection::new(Arc::new(tls_config), rustls_server_name.clone())
            .context("TLS client connection")?;
    let mut tls_stream = rustls::StreamOwned::new(tls_connector, initial_stream);

    // Force TLS handshake completion by doing a dummy read/write cycle
    use std::io::Write;
    tls_stream.flush().ok(); // Ensure handshake completes

    // Extract server public key before wrapping in Framed
    let server_public_key = extract_server_public_key(&tls_stream)?;

    let mut upgraded_framed = ironrdp_blocking::Framed::new(tls_stream);
    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);

    // 5. CredSSP + finalize connection
    tracing::info!("CredSSP/NLA authentication...");

    // Create stub network client (no Kerberos support, only username/password)
    let mut network_client = StubNetworkClient;

    let connection_result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector, // Now owned, not &mut
        &mut upgraded_framed,
        &mut network_client,
        server_name,
        server_public_key,
        None, // No kerberos config
    )
    .context("RDP connect_finalize (CredSSP/NLA) failed")?;

    // Use config resolution (user preference) instead of RDP file
    let width = config.default_width;
    let height = config.default_height;

    tracing::info!("Connected! Desktop: {}x{}", width, height);

    // 6. Create active stage for session handling
    let active_stage = ActiveStage::new(connection_result);

    Ok(RdpSession {
        framed: RdpFramed::Direct(upgraded_framed),
        active_stage,
        desktop_size: DesktopSize { width, height },
    })
}

/// Helper: Read a PDU with timeout (non-blocking)
fn read_pdu_timeout(
    framed: &mut RdpFramed,
    timeout_ms: u64,
) -> Result<Option<(ironrdp::pdu::Action, bytes::BytesMut)>> {
    use std::io;

    // Set read timeout
    let timeout = Duration::from_millis(timeout_ms);

    match framed {
        RdpFramed::Direct(f) => {
            // get_inner_mut() returns (&mut TlsStream, &mut BytesMut)
            let (stream, _) = f.get_inner_mut();
            stream.get_mut().set_read_timeout(Some(timeout)).ok();
            match f.read_pdu() {
                Ok(pdu) => Ok(Some(pdu)),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    Ok(None)
                }
                Err(e) => Err(anyhow::Error::from(e)),
            }
        }
        RdpFramed::Gateway(f) => {
            // For gateway connections, we can't easily set timeout on WebSocket
            // Just do a blocking read (WebSocket handles timeouts internally)
            match f.read_pdu() {
                Ok(pdu) => Ok(Some(pdu)),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    Ok(None)
                }
                Err(e) => Err(anyhow::Error::from(e)),
            }
        }
    }
}

/// RDP network loop - runs in a separate thread
///
/// This loop:
/// 1. Receives input events from the window thread
/// 2. Reads PDUs from the network
/// 3. Processes them through ActiveStage
/// 4. Sends framebuffer updates back to the window
pub fn rdp_network_loop(
    mut session: RdpSession,
    input_rx: mpsc::Receiver<InputEvent>,
    update_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    tracing::info!("RDP network loop started");

    // Create DecodedImage - IronRDP will automatically update it
    let mut image = DecodedImage::new(
        PixelFormat::RgbA32,
        session.desktop_size.width,
        session.desktop_size.height,
    );

    tracing::info!(
        "DecodedImage created: {}x{}, expected data size: {} bytes",
        session.desktop_size.width,
        session.desktop_size.height,
        session.desktop_size.width as usize * session.desktop_size.height as usize * 4
    );

    // Main event loop
    loop {
        // 1. Process input events (non-blocking)
        let mut input_events = Vec::new();
        while let Ok(event) = input_rx.try_recv() {
            match event {
                InputEvent::Shutdown => {
                    tracing::info!("Shutdown requested");
                    return Ok(());
                }
                InputEvent::Mouse(e) | InputEvent::Keyboard(e) => {
                    input_events.push(e);
                }
            }
        }

        // 2. Send input events to server
        if !input_events.is_empty() {
            tracing::trace!("Sending {} input events", input_events.len());
            let outputs = session
                .active_stage
                .process_fastpath_input(&mut image, &input_events)?;

            for out in outputs {
                if let ActiveStageOutput::ResponseFrame(frame) = out {
                    match &mut session.framed {
                        RdpFramed::Direct(f) => f.write_all(&frame)?,
                        RdpFramed::Gateway(f) => f.write_all(&frame)?,
                    }
                }
            }
        }

        // 3. Read PDU from network (with timeout)
        let pdu_result = read_pdu_timeout(&mut session.framed, 50)?;

        let (action, payload) = match pdu_result {
            Some(pdu) => pdu,
            None => continue, // Timeout, retry
        };

        // 4. Process the PDU
        let outputs = session.active_stage.process(&mut image, action, &payload)?;

        // 5. Handle outputs
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => {
                    // Send response to server
                    match &mut session.framed {
                        RdpFramed::Direct(f) => f.write_all(&frame)?,
                        RdpFramed::Gateway(f) => f.write_all(&frame)?,
                    }
                }
                ActiveStageOutput::GraphicsUpdate(rect) => {
                    // image.data() now contains updated pixels!
                    tracing::debug!(
                        "Graphics update received: {:?}, image data size: {} bytes",
                        rect,
                        image.data().len()
                    );

                    // Send the entire framebuffer (we'll optimize later)
                    if let Err(e) = update_tx.send(image.data().to_vec()) {
                        tracing::error!("Failed to send framebuffer update: {}", e);
                    }
                }
                ActiveStageOutput::Terminate(reason) => {
                    tracing::info!("Session terminated: {:?}", reason);
                    return Ok(());
                }
                _ => {}
            }
        }
    }
}
