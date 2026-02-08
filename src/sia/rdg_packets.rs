//! RDP Gateway Protocol Binary Packets
//!
//! This module implements the binary packet structures for MS-TSGU protocol.
//! All packets are sent through the IN/OUT HTTP channels.
//!
//! References:
//! - MS-TSGU: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/

use anyhow::{Result, bail};
use std::io::{Read, Write};

/// Packet types used in HTTP_PACKET_HEADER
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    HandshakeRequest = 0x0001,
    HandshakeResponse = 0x0002,
    TunnelCreate = 0x0003,
    TunnelResponse = 0x0004,
    TunnelAuth = 0x0005,
    TunnelAuthResponse = 0x0006,
    ChannelCreate = 0x0007,
    ChannelResponse = 0x0008,
    Data = 0x0009,
    ServiceMessage = 0x000A,
    Reauth = 0x000B,
}

impl PacketType {
    /// Converts a u16 to PacketType
    fn from_u16(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(PacketType::HandshakeRequest),
            0x0002 => Ok(PacketType::HandshakeResponse),
            0x0003 => Ok(PacketType::TunnelCreate),
            0x0004 => Ok(PacketType::TunnelResponse),
            0x0005 => Ok(PacketType::TunnelAuth),
            0x0006 => Ok(PacketType::TunnelAuthResponse),
            0x0007 => Ok(PacketType::ChannelCreate),
            0x0008 => Ok(PacketType::ChannelResponse),
            0x0009 => Ok(PacketType::Data),
            0x000A => Ok(PacketType::ServiceMessage),
            0x000B => Ok(PacketType::Reauth),
            _ => bail!("Unknown packet type: 0x{:04X}", value),
        }
    }
}

/// Extended authentication types
#[repr(u16)]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum ExtendedAuth {
    None = 0x0000,
    Paa = 0x0001,       // PAA authentication
    Smartcard = 0x0002, // Smart card
    Sspi = 0x0004,      // NTLM
}

/// HTTP packet header (8 bytes)
///
/// This is the common header for all RDG packets.
/// Format (little-endian):
/// - packetType: u16 (2 bytes)
/// - reserved: u16 (2 bytes) - must be 0
/// - packetLength: u32 (4 bytes) - total packet size including header
#[derive(Debug, Clone)]
pub struct HttpPacketHeader {
    pub packet_type: PacketType,
    pub packet_length: u32,
}

impl HttpPacketHeader {
    /// Creates a new packet header
    pub fn new(packet_type: PacketType, packet_length: u32) -> Self {
        Self {
            packet_type,
            packet_length,
        }
    }

    /// Writes the header to a writer (8 bytes, little-endian)
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&(self.packet_type as u16).to_le_bytes())?;
        writer.write_all(&0u16.to_le_bytes())?; // reserved
        writer.write_all(&self.packet_length.to_le_bytes())?;
        Ok(())
    }

    /// Reads a header from a reader (8 bytes, little-endian)
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 2];

        // Read packet type
        reader.read_exact(&mut buf)?;
        let packet_type = PacketType::from_u16(u16::from_le_bytes(buf))?;

        // Read reserved (skip)
        reader.read_exact(&mut buf)?;

        // Read packet length
        let mut buf4 = [0u8; 4];
        reader.read_exact(&mut buf4)?;
        let packet_length = u32::from_le_bytes(buf4);

        Ok(Self {
            packet_type,
            packet_length,
        })
    }
}

/// HTTP Handshake Request Packet
///
/// Sent by client to initiate RDG connection.
/// Total size: 14 bytes
#[derive(Debug, Clone)]
pub struct HttpHandshakeRequest {
    pub ver_major: u8,      // Protocol major version (1)
    pub ver_minor: u8,      // Protocol minor version (0)
    pub extended_auth: u16, // Extended authentication flags
}

impl HttpHandshakeRequest {
    /// Creates a new handshake request with PAA authentication
    pub fn new_with_paa() -> Self {
        Self {
            ver_major: 1,
            ver_minor: 0,
            extended_auth: ExtendedAuth::Paa as u16,
        }
    }

    /// Writes the complete packet (header + body) to a writer
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Total packet size: 8 (header) + 6 (body) = 14 bytes
        let header = HttpPacketHeader::new(PacketType::HandshakeRequest, 14);
        header.write(writer)?;

        // Write body
        writer.write_all(&[self.ver_major])?;
        writer.write_all(&[self.ver_minor])?;
        writer.write_all(&0u16.to_le_bytes())?; // clientVersion (must be 0)
        writer.write_all(&self.extended_auth.to_le_bytes())?;

        Ok(())
    }
}

/// HTTP Handshake Response Packet
///
/// Received from server in response to handshake request.
/// Total size: 18 bytes
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct HttpHandshakeResponse {
    pub error_code: u32,    // HRESULT (0 = success)
    pub ver_major: u8,      // Server protocol major version
    pub ver_minor: u8,      // Server protocol minor version
    pub extended_auth: u16, // Server supported auth methods
}

impl HttpHandshakeResponse {
    /// Reads the packet from a reader (expects header already read)
    pub fn read<R: Read>(reader: &mut R, header: &HttpPacketHeader) -> Result<Self> {
        if header.packet_length < 18 {
            bail!(
                "Handshake response too short: {} bytes",
                header.packet_length
            );
        }

        let mut buf4 = [0u8; 4];
        let mut buf2 = [0u8; 2];

        // Read error code
        reader.read_exact(&mut buf4)?;
        let error_code = u32::from_le_bytes(buf4);

        // Read version
        let mut ver = [0u8; 1];
        reader.read_exact(&mut ver)?;
        let ver_major = ver[0];
        reader.read_exact(&mut ver)?;
        let ver_minor = ver[0];

        // Read server version (skip)
        reader.read_exact(&mut buf2)?;

        // Read extended auth
        reader.read_exact(&mut buf2)?;
        let extended_auth = u16::from_le_bytes(buf2);

        Ok(Self {
            error_code,
            ver_major,
            ver_minor,
            extended_auth,
        })
    }

    /// Checks if the response indicates success
    pub fn is_success(&self) -> bool {
        self.error_code == 0
    }
}

/// HTTP Tunnel Packet (Create Tunnel Request)
///
/// Sent by client to create a tunnel.
/// Minimum size: 16 bytes (without optional fields)
#[derive(Debug, Clone)]
pub struct HttpTunnelPacket {
    pub caps_flags: u32,     // Capability flags
    pub fields_present: u16, // Indicates which optional fields are present
}

impl HttpTunnelPacket {
    /// Creates a new tunnel creation request
    pub fn new() -> Self {
        Self {
            caps_flags: 0x00000001, // HTTP_CAPABILITY_TYPE_QUAR_SOH (basic capability)
            fields_present: 0,      // No optional fields
        }
    }

    /// Writes the complete packet to a writer
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Total packet size: 8 (header) + 8 (body) = 16 bytes
        let header = HttpPacketHeader::new(PacketType::TunnelCreate, 16);
        header.write(writer)?;

        // Write body
        writer.write_all(&self.caps_flags.to_le_bytes())?;
        writer.write_all(&self.fields_present.to_le_bytes())?;
        writer.write_all(&0u16.to_le_bytes())?; // reserved

        Ok(())
    }
}

/// HTTP Tunnel Response Packet
///
/// Received from server in response to tunnel creation.
/// Minimum size: 20 bytes
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpTunnelResponse {
    pub server_version: u32, // Server version
    pub error_code: u32,     // HRESULT (0 = success)
    pub fields_present: u16, // Optional fields indicator
}

impl HttpTunnelResponse {
    /// Reads the packet from a reader (expects header already read)
    pub fn read<R: Read>(reader: &mut R, header: &HttpPacketHeader) -> Result<Self> {
        if header.packet_length < 20 {
            bail!("Tunnel response too short: {} bytes", header.packet_length);
        }

        let mut buf4 = [0u8; 4];
        let mut buf2 = [0u8; 2];

        // Read server version
        reader.read_exact(&mut buf4)?;
        let server_version = u32::from_le_bytes(buf4);

        // Read error code
        reader.read_exact(&mut buf4)?;
        let error_code = u32::from_le_bytes(buf4);

        // Read fields present
        reader.read_exact(&mut buf2)?;
        let fields_present = u16::from_le_bytes(buf2);

        // Read reserved (skip)
        reader.read_exact(&mut buf2)?;

        Ok(Self {
            server_version,
            error_code,
            fields_present,
        })
    }

    /// Checks if the response indicates success
    pub fn is_success(&self) -> bool {
        self.error_code == 0
    }
}

/// HTTP Tunnel Auth Packet
///
/// Sent by client for tunnel authentication.
/// Minimum size: 12 bytes (without auth data)
#[derive(Debug, Clone)]
pub struct HttpTunnelAuthPacket {
    pub fields_present: u16, // Optional fields indicator
}

impl HttpTunnelAuthPacket {
    /// Creates a new tunnel auth packet (no additional auth data needed with PAA)
    pub fn new() -> Self {
        Self {
            fields_present: 0, // No optional fields
        }
    }

    /// Writes the complete packet to a writer
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Total packet size: 8 (header) + 4 (body) = 12 bytes
        let header = HttpPacketHeader::new(PacketType::TunnelAuth, 12);
        header.write(writer)?;

        // Write body
        writer.write_all(&self.fields_present.to_le_bytes())?;
        writer.write_all(&0u16.to_le_bytes())?; // reserved

        Ok(())
    }
}

/// HTTP Tunnel Auth Response Packet
///
/// Received from server in response to tunnel auth.
/// Minimum size: 16 bytes
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpTunnelAuthResponse {
    pub error_code: u32,     // HRESULT (0 = success)
    pub fields_present: u16, // Optional fields indicator
}

impl HttpTunnelAuthResponse {
    /// Reads the packet from a reader (expects header already read)
    pub fn read<R: Read>(reader: &mut R, header: &HttpPacketHeader) -> Result<Self> {
        if header.packet_length < 16 {
            bail!(
                "Tunnel auth response too short: {} bytes",
                header.packet_length
            );
        }

        let mut buf4 = [0u8; 4];
        let mut buf2 = [0u8; 2];

        // Read error code
        reader.read_exact(&mut buf4)?;
        let error_code = u32::from_le_bytes(buf4);

        // Read fields present
        reader.read_exact(&mut buf2)?;
        let fields_present = u16::from_le_bytes(buf2);

        // Read reserved (skip)
        reader.read_exact(&mut buf2)?;

        Ok(Self {
            error_code,
            fields_present,
        })
    }

    /// Checks if the response indicates success
    pub fn is_success(&self) -> bool {
        self.error_code == 0
    }
}

/// HTTP Channel Packet (Create Channel Request)
///
/// Sent by client to create a data channel.
/// Size: varies based on target server name
#[derive(Debug, Clone)]
pub struct HttpChannelPacket {
    pub resources: Vec<String>, // Target resources (e.g., server names)
}

impl HttpChannelPacket {
    /// Creates a new channel creation request
    pub fn new(target_server: String, target_port: u16) -> Self {
        // Format: "server:port"
        let resource = format!("{}:{}", target_server, target_port);
        Self {
            resources: vec![resource],
        }
    }

    /// Writes the complete packet to a writer
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Calculate resource string size (UTF-16LE)
        let resource_str = self.resources.join(";");
        let utf16_chars: Vec<u16> = resource_str.encode_utf16().collect();
        let resource_bytes = utf16_chars.len() * 2;

        // Total packet size: 8 (header) + 4 (count) + 4 (length) + resource_bytes + 2 (null terminator)
        let packet_size = 8 + 4 + 4 + resource_bytes + 2;

        let header = HttpPacketHeader::new(PacketType::ChannelCreate, packet_size as u32);
        header.write(writer)?;

        // Write number of resources
        writer.write_all(&(self.resources.len() as u32).to_le_bytes())?;

        // Write resource string length (in bytes, including null terminator)
        writer.write_all(&((resource_bytes + 2) as u32).to_le_bytes())?;

        // Write resource string as UTF-16LE
        for ch in utf16_chars {
            writer.write_all(&ch.to_le_bytes())?;
        }

        // Write null terminator
        writer.write_all(&0u16.to_le_bytes())?;

        Ok(())
    }
}

/// HTTP Channel Response Packet
///
/// Received from server in response to channel creation.
/// Minimum size: 28 bytes
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpChannelResponse {
    pub error_code: u32,     // HRESULT (0 = success)
    pub fields_present: u16, // Optional fields indicator
    pub channel_id: u32,     // Assigned channel ID
}

impl HttpChannelResponse {
    /// Reads the packet from a reader (expects header already read)
    pub fn read<R: Read>(reader: &mut R, header: &HttpPacketHeader) -> Result<Self> {
        if header.packet_length < 28 {
            bail!("Channel response too short: {} bytes", header.packet_length);
        }

        let mut buf4 = [0u8; 4];
        let mut buf2 = [0u8; 2];

        // Read error code
        reader.read_exact(&mut buf4)?;
        let error_code = u32::from_le_bytes(buf4);

        // Read fields present
        reader.read_exact(&mut buf2)?;
        let fields_present = u16::from_le_bytes(buf2);

        // Read reserved (skip)
        reader.read_exact(&mut buf2)?;

        // Read channel ID (offset 0x10 in packet)
        // Skip to correct position (we're at byte 12, need to get to byte 16)
        let mut skip = [0u8; 4];
        reader.read_exact(&mut skip)?;

        reader.read_exact(&mut buf4)?;
        let channel_id = u32::from_le_bytes(buf4);

        Ok(Self {
            error_code,
            fields_present,
            channel_id,
        })
    }

    /// Checks if the response indicates success
    pub fn is_success(&self) -> bool {
        self.error_code == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_roundtrip() {
        let header = HttpPacketHeader::new(PacketType::HandshakeRequest, 100);
        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();

        let parsed = HttpPacketHeader::read(&mut buf.as_slice()).unwrap();
        assert_eq!(header.packet_type as u16, parsed.packet_type as u16);
        assert_eq!(header.packet_length, parsed.packet_length);
    }

    #[test]
    fn test_handshake_request_size() {
        let request = HttpHandshakeRequest::new_with_paa();
        let mut buf = Vec::new();
        request.write(&mut buf).unwrap();
        assert_eq!(buf.len(), 14); // 8 header + 6 body
    }
}
