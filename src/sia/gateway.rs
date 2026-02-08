//! RDP Gateway (RDG) protocol implementation
//!
//! This module implements the Microsoft Remote Desktop Gateway protocol (MS-TSGU).
//! It uses two HTTP channels for bidirectional communication:
//! - OUT channel: receives data from server (using RDG_OUT_DATA method, chunked encoding)
//! - IN channel: sends data to server (using RDG_IN_DATA method, chunked encoding)
//!
//! Authentication uses PAA (Pluggable Authentication Architecture) with SSO tokens.
//!
//! ## Connection Flow
//!
//! 1. Create OUT channel → HTTP 200 + 10-byte seed payload (ignored)
//! 2. Create IN channel → HTTP 200 + 10-byte seed payload (ignored)
//! 3. Send/receive binary RDG packets through chunked HTTP encoding
//! 4. RDG handshake → tunnel → channel → RDP data
//!
//! ## HTTP Chunked Encoding
//!
//! The OUT channel uses Transfer-Encoding: chunked. Data format:
//! ```text
//! [size in hex]\r\n
//! [data]\r\n
//! 0\r\n
//! \r\n
//! ```
//!
//! A state machine handles incremental parsing of chunks.
//!
//! See RDG_PROTOCOL.md for detailed documentation and diagrams.

use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use super::rdg_packets::*;

/// Gateway connection that handles communication with CyberArk RDP Gateway
pub struct GatewayConnection {
    gateway_host: String,
    gateway_port: u16,
    target_server: String,
    target_port: u16,
    paa_cookie: String, // SSO token for authentication
}

impl GatewayConnection {
    /// Creates a new gateway connection
    ///
    /// # Arguments
    /// * `gateway_hostname` - Gateway server hostname (can include :port)
    /// * `target_server` - Target RDP server to connect to
    /// * `target_port` - Target RDP server port
    /// * `paa_cookie` - SSO token for PAA authentication
    /// * `_password` - Password (not used in current implementation)
    pub fn new(
        gateway_hostname: &str,
        target_server: String,
        target_port: u16,
        paa_cookie: String,
        _password: String,
    ) -> Result<Self> {
        // Parse hostname and port (default to 443 if not specified)
        let (gateway_host, gateway_port) =
            if let Some((host, port_str)) = gateway_hostname.split_once(':') {
                let port = port_str
                    .parse::<u16>()
                    .with_context(|| format!("Invalid gateway port: {}", port_str))?;
                (host.to_string(), port)
            } else {
                (gateway_hostname.to_string(), 443)
            };

        Ok(Self {
            gateway_host,
            gateway_port,
            target_server,
            target_port,
            paa_cookie,
        })
    }

    /// Establishes connection to the gateway and creates the dual HTTP channels
    pub fn connect(&self) -> Result<GatewayStream> {
        tracing::info!(
            "Connecting to RDP Gateway {}:{} for target {}:{}",
            self.gateway_host,
            self.gateway_port,
            self.target_server,
            self.target_port
        );

        // Generate unique IDs for this connection
        let connection_id = uuid::Uuid::new_v4();
        let correlation_id = uuid::Uuid::new_v4();

        // Step 1: Resolve gateway hostname to IP address
        // We connect once to get the IP, then reuse it for all subsequent connections
        // This avoids load balancing issues (same IP = same server instance)
        let (temp_stream, peer_addr) = self.connect_https(None)?;
        drop(temp_stream); // We only needed the IP address
        tracing::info!("Gateway resolved to: {}", peer_addr);

        // Step 2: Create OUT channel (server sends data to us through this channel)
        let (out_channel, initial_buffer) =
            self.create_out_channel(&connection_id, &correlation_id, peer_addr)?;

        // Step 3: Create IN channel (we send data to server through this channel)
        let in_channel = self.create_in_channel(&connection_id, &correlation_id, peer_addr)?;

        tracing::info!("RDP Gateway channels established");

        // Create stream wrapper with initial buffer from OUT channel HTTP response
        let mut stream = GatewayStream::new(in_channel, out_channel, initial_buffer);

        // Step 4: Execute RDG protocol handshake sequence
        tracing::info!("Starting RDG protocol handshake");
        self.rdg_protocol_handshake(&mut stream)?;

        tracing::info!("RDG protocol handshake complete - ready for RDP data");
        Ok(stream)
    }

    /// Creates an HTTPS connection to the gateway
    ///
    /// # Arguments
    /// * `peer_addr` - Optional peer address to connect to directly (for load balancing)
    ///
    /// # Returns
    /// A tuple containing the TLS stream and the peer address
    fn connect_https(
        &self,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> Result<(
        rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
        std::net::SocketAddr,
    )> {
        // Connect to specific IP if provided, or resolve hostname
        let tcp_stream = if let Some(addr) = peer_addr {
            TcpStream::connect(addr).with_context(|| format!("Failed to connect to {}", addr))?
        } else {
            let addr = format!("{}:{}", self.gateway_host, self.gateway_port);
            TcpStream::connect(&addr).with_context(|| format!("Failed to connect to {}", addr))?
        };

        let peer_addr = tcp_stream
            .peer_addr()
            .context("Failed to get peer address")?;

        // Setup TLS (HTTPS)
        let mut root_store = rustls::RootCertStore::empty();
        let cert_result = rustls_native_certs::load_native_certs();
        for cert in cert_result.certs {
            root_store.add(cert).ok();
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = rustls::pki_types::ServerName::try_from(self.gateway_host.clone())
            .with_context(|| format!("Invalid hostname: {}", self.gateway_host))?;

        let client = rustls::ClientConnection::new(Arc::new(config), server_name)
            .context("Failed to create TLS connection")?;

        Ok((rustls::StreamOwned::new(client, tcp_stream), peer_addr))
    }

    /// Helper function to extract HTTP body data from response buffer
    ///
    /// Finds the end of HTTP headers (`\r\n\r\n`) and returns the remaining data.
    fn extract_http_body(buffer: &[u8], len: usize) -> Vec<u8> {
        // Look for end of HTTP headers (\r\n\r\n)
        for i in 0..len.saturating_sub(3) {
            if &buffer[i..i + 4] == b"\r\n\r\n" {
                let body_start = i + 4;
                tracing::debug!(
                    "Found HTTP body at offset {}, {} bytes of body data",
                    body_start,
                    len - body_start
                );
                return buffer[body_start..len].to_vec();
            }
        }
        tracing::warn!("No HTTP body separator found in response");
        Vec::new()
    }

    /// Creates the OUT channel (server → client data flow)
    ///
    /// This channel uses the RDG_OUT_DATA HTTP method and requires PAA authentication.
    /// The server will first respond with 401, then we retry with the PAA token.
    fn create_out_channel(
        &self,
        connection_id: &uuid::Uuid,
        correlation_id: &uuid::Uuid,
        peer_addr: std::net::SocketAddr,
    ) -> Result<(
        rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
        Vec<u8>,
    )> {
        let (mut stream, _) = self.connect_https(Some(peer_addr))?;

        // Build HTTP request with RDG_OUT_DATA method
        let request = format!(
            "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: MS-RDGateway/1.0\r\n\
             Connection: Keep-Alive\r\n\
             RDG-Connection-Id: {}\r\n\
             RDG-Correlation-Id: {}\r\n\
             \r\n",
            self.gateway_host, connection_id, correlation_id
        );

        // Send initial request (expecting 401 Unauthorized)
        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // Read server response
        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response)?;
        let response_str = String::from_utf8_lossy(&response[..n]);

        tracing::debug!(
            "OUT channel initial HTTP response ({} bytes):\n{}",
            n,
            String::from_utf8_lossy(&response[..n.min(500)])
        );

        // Handle 401 response by retrying with PAA authentication
        if response_str.starts_with("HTTP/1.1 401") || response_str.starts_with("HTTP/1.0 401") {
            tracing::info!("Authenticating OUT channel with PAA token");

            // Resend request with Authorization header
            let auth_request = format!(
                "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: MS-RDGateway/1.0\r\n\
                 Connection: Keep-Alive\r\n\
                 Authorization: PAA {}\r\n\
                 RDG-Connection-Id: {}\r\n\
                 RDG-Correlation-Id: {}\r\n\
                 \r\n",
                self.gateway_host, self.paa_cookie, connection_id, correlation_id
            );

            stream.write_all(auth_request.as_bytes())?;
            stream.flush()?;

            // Read authenticated response
            let mut auth_response = vec![0u8; 4096];
            let n = stream.read(&mut auth_response)?;
            let auth_response_str = String::from_utf8_lossy(&auth_response[..n]);

            tracing::debug!(
                "OUT channel HTTP response ({} bytes):\n{}",
                n,
                String::from_utf8_lossy(&auth_response[..n.min(500)])
            );

            if !auth_response_str.starts_with("HTTP/1.1 200")
                && !auth_response_str.starts_with("HTTP/1.0 200")
            {
                bail!(
                    "OUT channel authentication failed: {}",
                    auth_response_str.lines().next().unwrap_or("Unknown error")
                );
            }

            // Extract body data (after HTTP headers)
            let body_data = Self::extract_http_body(&auth_response, n);
            tracing::info!("OUT channel established");
            return Ok((stream, body_data));
        } else if !response_str.starts_with("HTTP/1.1 200")
            && !response_str.starts_with("HTTP/1.0 200")
        {
            bail!(
                "OUT channel failed: {}",
                response_str.lines().next().unwrap_or("Unknown error")
            );
        }

        // Extract body data (after HTTP headers) for non-PAA case
        let body_data = Self::extract_http_body(&response, n);
        tracing::info!("OUT channel established");
        Ok((stream, body_data))
    }

    /// Creates the IN channel (client → server data flow)
    ///
    /// This channel uses the RDG_IN_DATA HTTP method with chunked encoding.
    /// Like OUT channel, it requires PAA authentication.
    fn create_in_channel(
        &self,
        connection_id: &uuid::Uuid,
        correlation_id: &uuid::Uuid,
        peer_addr: std::net::SocketAddr,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
        let (mut stream, _) = self.connect_https(Some(peer_addr))?;

        // Build HTTP request with RDG_IN_DATA method and chunked encoding
        let request = format!(
            "RDG_IN_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: MS-RDGateway/1.0\r\n\
             Connection: Keep-Alive\r\n\
             Transfer-Encoding: chunked\r\n\
             RDG-Connection-Id: {}\r\n\
             RDG-Correlation-Id: {}\r\n\
             \r\n",
            self.gateway_host, connection_id, correlation_id
        );

        // Send initial request (expecting 401)
        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // Read server response
        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response)?;
        let response_str = String::from_utf8_lossy(&response[..n]);

        // Handle 401 response by retrying with PAA authentication
        if response_str.starts_with("HTTP/1.1 401") || response_str.starts_with("HTTP/1.0 401") {
            tracing::info!("Authenticating IN channel with PAA token");

            // Resend with Authorization header
            let auth_request = format!(
                "RDG_IN_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: MS-RDGateway/1.0\r\n\
                 Connection: Keep-Alive\r\n\
                 Authorization: PAA {}\r\n\
                 Transfer-Encoding: chunked\r\n\
                 RDG-Connection-Id: {}\r\n\
                 RDG-Correlation-Id: {}\r\n\
                 \r\n",
                self.gateway_host, self.paa_cookie, connection_id, correlation_id
            );

            stream.write_all(auth_request.as_bytes())?;
            stream.flush()?;

            // Read authenticated response
            let mut auth_response = vec![0u8; 4096];
            let n = stream.read(&mut auth_response)?;
            let auth_response_str = String::from_utf8_lossy(&auth_response[..n]);

            if !auth_response_str.starts_with("HTTP/1.1 200")
                && !auth_response_str.starts_with("HTTP/1.0 200")
            {
                bail!(
                    "IN channel authentication failed: {}",
                    auth_response_str.lines().next().unwrap_or("Unknown error")
                );
            }
        } else if !response_str.starts_with("HTTP/1.1 200")
            && !response_str.starts_with("HTTP/1.0 200")
        {
            bail!(
                "IN channel failed: {}",
                response_str.lines().next().unwrap_or("Unknown error")
            );
        }

        tracing::info!("IN channel established");
        Ok(stream)
    }

    /// Executes the complete RDG protocol handshake sequence
    ///
    /// This sends and receives binary packets through the IN/OUT channels
    /// following the MS-TSGU protocol specification.
    ///
    /// Sequence:
    /// 1. Handshake (negotiate protocol version and auth)
    /// 2. Tunnel creation (establish tunnel with capabilities)
    /// 3. Tunnel authentication (authenticate the tunnel)
    /// 4. Channel creation (create data channel for RDP traffic)
    fn rdg_protocol_handshake(&self, stream: &mut GatewayStream) -> Result<()> {
        // Step 1: Handshake
        tracing::info!("Sending handshake request");
        let handshake_req = HttpHandshakeRequest::new_with_paa();
        stream.write_rdg_packet(&handshake_req)?;

        tracing::info!("Waiting for handshake response");
        let handshake_resp = stream.read_handshake_response()?;
        if !handshake_resp.is_success() {
            bail!(
                "Handshake failed with error code: 0x{:08X}",
                handshake_resp.error_code
            );
        }
        tracing::info!("Handshake successful");

        // Step 2: Tunnel creation
        tracing::info!("Creating tunnel");
        let tunnel_req = HttpTunnelPacket::new();
        stream.write_rdg_packet(&tunnel_req)?;

        tracing::info!("Waiting for tunnel response");
        let tunnel_resp = stream.read_tunnel_response()?;
        if !tunnel_resp.is_success() {
            bail!(
                "Tunnel creation failed with error code: 0x{:08X}",
                tunnel_resp.error_code
            );
        }
        tracing::info!("Tunnel created successfully");

        // Step 3: Tunnel authentication
        tracing::info!("Authenticating tunnel");
        let auth_req = HttpTunnelAuthPacket::new();
        stream.write_rdg_packet(&auth_req)?;

        tracing::info!("Waiting for auth response");
        let auth_resp = stream.read_tunnel_auth_response()?;
        if !auth_resp.is_success() {
            bail!(
                "Tunnel auth failed with error code: 0x{:08X}",
                auth_resp.error_code
            );
        }
        tracing::info!("Tunnel authenticated");

        // Step 4: Channel creation
        tracing::info!(
            "Creating data channel for {}:{}",
            self.target_server,
            self.target_port
        );
        let channel_req = HttpChannelPacket::new(self.target_server.clone(), self.target_port);
        stream.write_rdg_packet(&channel_req)?;

        tracing::info!("Waiting for channel response");
        let channel_resp = stream.read_channel_response()?;
        if !channel_resp.is_success() {
            bail!(
                "Channel creation failed with error code: 0x{:08X}",
                channel_resp.error_code
            );
        }
        tracing::info!("Data channel created (ID: {})", channel_resp.channel_id);

        Ok(())
    }
}

/// State machine for HTTP chunked transfer encoding decoder
///
/// This tracks the current position in the chunk reading process.
/// Based on FreeRDP's implementation (rdg.c).
#[derive(Debug)]
struct ChunkedState {
    state: ChunkStateEnum,
    next_offset: usize,       // Bytes remaining in current chunk
    header_footer_pos: usize, // Position in header/footer reading
    len_buffer: Vec<u8>,      // Buffer for hex size reading
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkStateEnum {
    LengthHeader, // Reading chunk size (hex format)
    Data,         // Reading chunk data
    Footer,       // Reading trailing \r\n
    End,          // End of stream
}

impl ChunkedState {
    fn new() -> Self {
        Self {
            state: ChunkStateEnum::LengthHeader,
            next_offset: 0,
            header_footer_pos: 0,
            len_buffer: Vec::new(),
        }
    }
}

/// Stream that wraps the dual HTTP channels (IN and OUT)
///
/// This implements Read and Write traits so it can be used like a normal stream.
/// Data written to this stream goes through the IN channel (chunked encoding).
/// Data read from this stream comes from the OUT channel (chunked encoding).
///
/// Uses a state machine to decode HTTP chunked encoding incrementally,
/// similar to FreeRDP's implementation.
pub struct GatewayStream {
    in_channel: Arc<Mutex<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>>,
    out_channel: Arc<Mutex<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>>,
    read_buffer: Vec<u8>, // Decoded data ready to be read
    read_pos: usize,
    pending_bytes: Vec<u8>, // Raw HTTP bytes not yet processed by chunked decoder
    pending_pos: usize,
    chunk_state: ChunkedState,
}

impl GatewayStream {
    fn new(
        in_channel: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
        out_channel: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
        seed_payload: Vec<u8>,
    ) -> Self {
        // Per MS-TSGU spec: "The server sends back the final status code 200 OK,
        // and a random entity body of limited size (100 bytes)"
        // In practice, it's 10 bytes according to FreeRDP implementation.
        // This seed payload must be SKIPPED before reading actual chunked data.
        tracing::info!(
            "Skipping {} bytes of seed payload after HTTP 200 OK",
            seed_payload.len()
        );

        Self {
            in_channel: Arc::new(Mutex::new(in_channel)),
            out_channel: Arc::new(Mutex::new(out_channel)),
            read_buffer: Vec::new(), // Empty - will be filled by chunk decoder
            read_pos: 0,
            pending_bytes: Vec::new(), // Start empty - seed is skipped
            pending_pos: 0,
            chunk_state: ChunkedState::new(),
        }
    }

    /// Helper to read one byte either from pending_bytes or from the socket
    fn read_one_byte(
        pending_bytes: &[u8],
        pending_pos: &mut usize,
        out: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    ) -> std::io::Result<Option<u8>> {
        // First check if we have pending bytes
        if *pending_pos < pending_bytes.len() {
            let byte = pending_bytes[*pending_pos];
            *pending_pos += 1;
            return Ok(Some(byte));
        }

        // No pending bytes, read from socket
        let mut byte = [0u8; 1];
        match out.read(&mut byte) {
            Ok(0) => Ok(None), // EOF
            Ok(_) => Ok(Some(byte[0])),
            Err(e) => Err(e),
        }
    }

    /// Reads data from OUT channel using HTTP chunked encoding state machine
    ///
    /// This implements a non-blocking state machine similar to FreeRDP's
    /// http_chuncked_read() function. It can handle partial reads and will
    /// return immediately with whatever data is available.
    ///
    /// HTTP chunked encoding format:
    /// - Chunk size in hexadecimal + \r\n
    /// - Chunk data
    /// - \r\n
    ///
    /// Returns the number of bytes read (0 = end of stream, >0 = data available)
    fn read_chunk_stateful(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut out = self.out_channel.lock().unwrap();
        let mut effective_len = 0;

        tracing::trace!(
            "read_chunk_stateful: buf.len()={}, state={:?}",
            buf.len(),
            self.chunk_state.state
        );

        let mut buf_remaining = buf;

        loop {
            match self.chunk_state.state {
                ChunkStateEnum::LengthHeader => {
                    // Read chunk size header byte by byte until we hit \n
                    // Try to read one byte (from pending or socket)
                    let read_result =
                        Self::read_one_byte(&self.pending_bytes, &mut self.pending_pos, &mut out);
                    tracing::trace!("LengthHeader: read_result={:?}", read_result);

                    match read_result {
                        Ok(None) => {
                            // EOF - return what we have so far
                            tracing::warn!(
                                "LengthHeader: EOF detected, effective_len={}",
                                effective_len
                            );
                            return if effective_len > 0 {
                                Ok(effective_len)
                            } else {
                                Ok(0)
                            };
                        }
                        Ok(Some(byte)) => {
                            self.chunk_state.len_buffer.push(byte);

                            // Check if we hit newline (end of size header)
                            if byte == b'\n' {
                                // Parse hex size (remove \r\n)
                                let size_str =
                                    String::from_utf8_lossy(&self.chunk_state.len_buffer);
                                let size_str = size_str
                                    .trim()
                                    .trim_end_matches('\n')
                                    .trim_end_matches('\r');

                                let chunk_size =
                                    usize::from_str_radix(size_str, 16).map_err(|e| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            format!("Invalid chunk size '{}': {}", size_str, e),
                                        )
                                    })?;

                                tracing::trace!("Chunk size parsed: {} bytes", chunk_size);

                                if chunk_size == 0 {
                                    // Chunk size 0 = end of stream
                                    self.chunk_state.state = ChunkStateEnum::End;
                                    return Ok(effective_len);
                                }

                                self.chunk_state.next_offset = chunk_size;
                                self.chunk_state.state = ChunkStateEnum::Data;
                                self.chunk_state.len_buffer.clear();
                            }

                            // Prevent infinite buffer growth (malformed chunk)
                            if self.chunk_state.len_buffer.len() > 20 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "Chunk size header too long",
                                ));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // No data available right now, return what we have
                            return Ok(effective_len);
                        }
                        Err(e) => {
                            return if effective_len > 0 {
                                Ok(effective_len)
                            } else {
                                Err(e)
                            };
                        }
                    }
                }

                ChunkStateEnum::Data => {
                    // Read chunk data (limited by next_offset and buffer size)
                    let to_read = buf_remaining.len().min(self.chunk_state.next_offset);

                    if to_read == 0 {
                        // Buffer is full, return what we have
                        return Ok(effective_len);
                    }

                    // First try to read from pending_bytes
                    let mut bytes_read = 0;
                    if self.pending_pos < self.pending_bytes.len() {
                        let pending_available = self.pending_bytes.len() - self.pending_pos;
                        let from_pending = to_read.min(pending_available);
                        buf_remaining[..from_pending].copy_from_slice(
                            &self.pending_bytes[self.pending_pos..self.pending_pos + from_pending],
                        );
                        self.pending_pos += from_pending;
                        bytes_read = from_pending;
                    }

                    // If we still need more data and haven't filled the request, read from socket
                    let read_result = if bytes_read < to_read {
                        match out.read(&mut buf_remaining[bytes_read..to_read]) {
                            Ok(socket_bytes) => Ok(bytes_read + socket_bytes),
                            Err(e) if bytes_read > 0 => Ok(bytes_read), // Return pending data even if socket fails
                            Err(e) => Err(e),
                        }
                    } else {
                        Ok(bytes_read)
                    };

                    match read_result {
                        Ok(0) if bytes_read == 0 => {
                            // EOF in middle of chunk
                            return if effective_len > 0 {
                                Ok(effective_len)
                            } else {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "EOF while reading chunk data",
                                ))
                            };
                        }
                        Ok(n) => {
                            self.chunk_state.next_offset -= n;
                            effective_len += n;

                            tracing::trace!(
                                "Read {} bytes from chunk, {} remaining",
                                n,
                                self.chunk_state.next_offset
                            );

                            // Check if chunk is complete
                            if self.chunk_state.next_offset == 0 {
                                self.chunk_state.state = ChunkStateEnum::Footer;
                                self.chunk_state.header_footer_pos = 0;
                            }

                            // If we filled the buffer, return immediately
                            if n == buf_remaining.len() {
                                return Ok(effective_len);
                            }

                            // Otherwise, continue reading (might have more data or next chunk)
                            buf_remaining = &mut buf_remaining[n..];
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(effective_len);
                        }
                        Err(e) => {
                            return if effective_len > 0 {
                                Ok(effective_len)
                            } else {
                                Err(e)
                            };
                        }
                    }
                }

                ChunkStateEnum::Footer => {
                    // Read trailing \r\n (2 bytes)
                    match Self::read_one_byte(&self.pending_bytes, &mut self.pending_pos, &mut out)
                    {
                        Ok(None) => {
                            return if effective_len > 0 {
                                Ok(effective_len)
                            } else {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "EOF while reading chunk footer",
                                ))
                            };
                        }
                        Ok(Some(_byte)) => {
                            self.chunk_state.header_footer_pos += 1;

                            // After reading 2 bytes (\r\n), move to next chunk
                            if self.chunk_state.header_footer_pos == 2 {
                                self.chunk_state.state = ChunkStateEnum::LengthHeader;
                                self.chunk_state.header_footer_pos = 0;

                                // If we have data, return it now
                                // Next read will start the next chunk
                                if effective_len > 0 {
                                    return Ok(effective_len);
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(effective_len);
                        }
                        Err(e) => {
                            return if effective_len > 0 {
                                Ok(effective_len)
                            } else {
                                Err(e)
                            };
                        }
                    }
                }

                ChunkStateEnum::End => {
                    // Stream ended
                    return Ok(0);
                }
            }
        }
    }

    /// Writes data as an HTTP chunk to the IN channel
    ///
    /// HTTP chunked encoding format:
    /// - Chunk size in hexadecimal + \r\n
    /// - Chunk data
    /// - \r\n
    fn write_chunk(&mut self, data: &[u8]) -> std::io::Result<()> {
        let mut in_chan = self.in_channel.lock().unwrap();

        // Write chunk size in hexadecimal
        let size_line = format!("{:X}\r\n", data.len());
        tracing::trace!("Writing chunk: size={} ({})", data.len(), size_line.trim());
        in_chan.write_all(size_line.as_bytes())?;

        // Write chunk data
        in_chan.write_all(data)?;

        // Write trailing \r\n
        in_chan.write_all(b"\r\n")?;

        tracing::trace!("Chunk written successfully");
        Ok(())
    }

    /// Writes an RDG packet through the IN channel
    ///
    /// The packet is serialized and sent as an HTTP chunk.
    pub fn write_rdg_packet<P>(&mut self, packet: &P) -> Result<()>
    where
        P: RdgPacketWrite,
    {
        let mut buf = Vec::new();
        packet.write_packet(&mut buf)?;
        tracing::debug!("Sending RDG packet: {} bytes", buf.len());
        self.write_chunk(&buf)?;

        // Flush to ensure packet is sent immediately
        let mut in_chan = self.in_channel.lock().unwrap();
        in_chan.flush()?;

        Ok(())
    }

    /// Reads a handshake response packet from the OUT channel
    pub fn read_handshake_response(&mut self) -> Result<HttpHandshakeResponse> {
        let header = self.read_packet_header()?;
        if header.packet_type != PacketType::HandshakeResponse {
            bail!("Expected HandshakeResponse, got {:?}", header.packet_type);
        }

        let mut body_buf = vec![0u8; (header.packet_length - 8) as usize];
        self.read_exact(&mut body_buf)?;

        HttpHandshakeResponse::read(&mut body_buf.as_slice(), &header)
    }

    /// Reads a tunnel response packet from the OUT channel
    pub fn read_tunnel_response(&mut self) -> Result<HttpTunnelResponse> {
        let header = self.read_packet_header()?;
        if header.packet_type != PacketType::TunnelResponse {
            bail!("Expected TunnelResponse, got {:?}", header.packet_type);
        }

        let mut body_buf = vec![0u8; (header.packet_length - 8) as usize];
        self.read_exact(&mut body_buf)?;

        HttpTunnelResponse::read(&mut body_buf.as_slice(), &header)
    }

    /// Reads a tunnel auth response packet from the OUT channel
    pub fn read_tunnel_auth_response(&mut self) -> Result<HttpTunnelAuthResponse> {
        let header = self.read_packet_header()?;
        if header.packet_type != PacketType::TunnelAuthResponse {
            bail!("Expected TunnelAuthResponse, got {:?}", header.packet_type);
        }

        let mut body_buf = vec![0u8; (header.packet_length - 8) as usize];
        self.read_exact(&mut body_buf)?;

        HttpTunnelAuthResponse::read(&mut body_buf.as_slice(), &header)
    }

    /// Reads a channel response packet from the OUT channel
    pub fn read_channel_response(&mut self) -> Result<HttpChannelResponse> {
        let header = self.read_packet_header()?;
        if header.packet_type != PacketType::ChannelResponse {
            bail!("Expected ChannelResponse, got {:?}", header.packet_type);
        }

        let mut body_buf = vec![0u8; (header.packet_length - 8) as usize];
        self.read_exact(&mut body_buf)?;

        HttpChannelResponse::read(&mut body_buf.as_slice(), &header)
    }

    /// Reads an RDG packet header (8 bytes)
    fn read_packet_header(&mut self) -> Result<HttpPacketHeader> {
        let mut header_buf = [0u8; 8];
        self.read_exact(&mut header_buf)?;
        HttpPacketHeader::read(&mut header_buf.as_slice())
    }

    /// Reads exact number of bytes (helper for reading packet bodies)
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut total_read = 0;
        while total_read < buf.len() {
            let n = self.read(&mut buf[total_read..])?;
            if n == 0 {
                bail!("Unexpected end of stream while reading packet");
            }
            total_read += n;
        }
        Ok(())
    }
}

/// Trait for packets that can be written to a stream
pub(crate) trait RdgPacketWrite {
    fn write_packet<W: Write>(&self, writer: &mut W) -> Result<()>;
}

// Implement the trait for all our packet types
impl RdgPacketWrite for HttpHandshakeRequest {
    fn write_packet<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.write(writer)
    }
}

impl RdgPacketWrite for HttpTunnelPacket {
    fn write_packet<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.write(writer)
    }
}

impl RdgPacketWrite for HttpTunnelAuthPacket {
    fn write_packet<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.write(writer)
    }
}

impl RdgPacketWrite for HttpChannelPacket {
    fn write_packet<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.write(writer)
    }
}

// Implement Read trait so GatewayStream can be used like any readable stream
impl Read for GatewayStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If we have buffered data from a previous read, return that first
        if self.read_pos < self.read_buffer.len() {
            let available = self.read_buffer.len() - self.read_pos;
            let to_copy = buf.len().min(available);
            buf[..to_copy]
                .copy_from_slice(&self.read_buffer[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;

            // Clear buffer if we've read everything
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Ok(to_copy);
        }

        // Read next chunk from OUT channel using state machine
        self.read_chunk_stateful(buf)
    }
}

// Implement Write trait so GatewayStream can be used like any writable stream
impl Write for GatewayStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Write data as a chunk to IN channel
        self.write_chunk(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut in_chan = self.in_channel.lock().unwrap();
        in_chan.flush()
    }
}
