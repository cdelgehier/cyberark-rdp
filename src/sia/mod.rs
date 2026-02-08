//! SIA Connect (RDP Gateway) implementation
//!
//! This module implements the MS-TSGU protocol for connecting to RDP servers
//! through an HTTP(S) gateway. Used by CyberArk SIA Connect.
//!
//! See RDG_PROTOCOL.md for detailed protocol documentation.

pub mod gateway;
pub mod rdg_packets;

pub use gateway::{GatewayConnection, GatewayStream};
