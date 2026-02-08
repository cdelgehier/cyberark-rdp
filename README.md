# cyberark-rdp

Native macOS RDP client for CyberArk Privilege Cloud. No XQuartz, no FreeRDP — pure Rust.

## Features

- 📄 Opens `.rdp` files downloaded from CyberArk
- 🔐 Prompts for the daily CyberArk password
- 🖥️ Native macOS window (no X11/XQuartz needed)
- ⚙️ YAML config for persistent settings (`cert_ignore`, `resize`, resolution)
- 🦀 Built on [IronRDP](https://github.com/Devolutions/IronRDP) by Devolutions

## CyberArk Compatibility

This client supports **CyberArk PSM (Legacy mode)** connections:

- ✅ Username format: `domain\user@uuid` (automatically parsed)
- ✅ CredSSP disabled by default (CyberArk sets `EnableCredSspSupport:i:0`)
- ✅ TLS standard authentication
- ⚠️ **SIA Connect (Gateway mode)** is implemented but currently non-functional with CyberArk servers

**Note**: CyberArk automatically generates RDP files with the correct settings. No manual configuration needed.

## Install

```bash
# From source
cargo install --path .

# Or just build
cargo build --release
```

## Usage

### As a command-line tool

```bash
# Open an RDP file (will prompt for password)
cyberark-rdp ~/Downloads/session.rdp

# With explicit username/password
cyberark-rdp ~/Downloads/session.rdp -u myuser -p 'MyPassword'

# Debug: dump parsed RDP file
cyberark-rdp ~/Downloads/session.rdp --dump-rdp
```

### As default .rdp handler on macOS

1. Build: `cargo build --release`
2. Create an `.app` bundle (see below)
3. Associate `.rdp` files with the app in Finder (⌘-i → Open With)

## Configuration

Config is stored in `~/.config/cyberark-rdp/config.yaml`:

```yaml
# Skip TLS certificate verification (like /cert:ignore in xfreerdp)
cert_ignore: true

# Allow dynamic window resize
resize: false

# Default desktop resolution
default_width: 1280
default_height: 1024
```

The config file is auto-created with defaults on first run.

## macOS .app Bundle

To use as a Finder-associated app for `.rdp` files, create a minimal `.app` bundle:

```bash
APP_DIR="$HOME/Applications/CyberArk RDP.app"
mkdir -p "$APP_DIR/Contents/MacOS"

# Copy binary
cp target/release/cyberark-rdp "$APP_DIR/Contents/MacOS/"

# Create Info.plist
cat > "$APP_DIR/Contents/Info.plist" << 'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>CyberArk RDP</string>
    <key>CFBundleIdentifier</key>
    <string>com.cyberark-rdp</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundleExecutable</key>
    <string>cyberark-rdp</string>
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeExtensions</key>
            <array>
                <string>rdp</string>
            </array>
            <key>CFBundleTypeName</key>
            <string>RDP Connection File</string>
            <key>CFBundleTypeRole</key>
            <string>Viewer</string>
        </dict>
    </array>
</dict>
</plist>
XML
```

Then in Finder, select any `.rdp` file → ⌘-i → Open With → CyberArk RDP → Change All.

## Architecture

```
src/
├── main.rs          # CLI (clap), password prompt, orchestration
├── config.rs        # ~/.config/cyberark-rdp/config.yaml (serde)
├── rdp_parser.rs    # .rdp file parser (key:type:value)
├── connection.rs    # IronRDP connection (TLS, CredSSP/NLA)
└── window.rs        # Native window (winit + softbuffer)
```

## Dependencies

- [IronRDP](https://github.com/Devolutions/IronRDP) — Rust RDP protocol implementation
- [winit](https://github.com/rust-windowing/winit) — Cross-platform window creation
- [softbuffer](https://github.com/rust-windowing/softbuffer) — Software framebuffer rendering
- [rustls](https://github.com/rustls/rustls) — TLS implementation
- [clap](https://github.com/clap-rs/clap) — CLI argument parsing
- [rfd](https://github.com/PolyMeilex/rfd) — Native file/message dialogs

## Project Status

### ✅ Implemented
- RDP file parsing (username, hostname, gateway settings, SSO tokens)
- PAA (Pluggable Authentication Architecture) authentication with SSO tokens
- Dual HTTP channel establishment (IN and OUT) with RDP Gateway
- HTTP chunked encoding for data transfer
- TLS/HTTPS connections to CyberArk gateway

### ⚠️ In Progress
- **RDP Gateway protocol completion**: Channels are established, but binary packet exchange needs implementation:
  1. HTTP_HANDSHAKE_REQUEST/RESPONSE packets
  2. HTTP_TUNNEL_PACKET/RESPONSE packets
  3. HTTP_TUNNEL_AUTH_PACKET/RESPONSE packets
  4. HTTP_CHANNEL_PACKET/RESPONSE packets

### 📋 TODO

#### Core RDP Features
- [ ] Complete RDP Gateway protocol (MS-TSGU binary packets)
- [ ] Forward keyboard input to RDP session
- [ ] Forward mouse input to RDP session
- [ ] Render RDP framebuffer updates
- [ ] Dynamic resize (send RDP resize PDU)

#### Additional Features
- [ ] Drive redirection (`/drive:home` equivalent)
- [ ] Clipboard sharing
- [ ] macOS .app bundle build script
- [ ] Automate CyberArk password retrieval via CyberArk API

## Technical Notes

### RDP Gateway Implementation

The gateway module (`src/gateway.rs`) implements Microsoft's RDP Gateway protocol (MS-TSGU) using two HTTP channels:

**OUT Channel** (`RDG_OUT_DATA`):
- Receives data from server to client
- Standard HTTP response with chunked encoding

**IN Channel** (`RDG_IN_DATA`):
- Sends data from client to server
- HTTP chunked transfer encoding

**Authentication Flow**:
1. Initial request (GET/POST) → Server responds 401 Unauthorized
2. Retry with `Authorization: PAA <sso_token>` → Server responds 200 OK
3. Channels are established

**Load Balancing**:
The implementation resolves the gateway hostname once and reuses the same IP address for all connections. This prevents issues with load-balanced servers using different session keys.

### SSO Token Notes

⚠️ **Important**: SSO tokens in CyberArk RDP files are single-use. If authentication fails, download a fresh RDP file from CyberArk.

## References

- [MS-TSGU: Remote Desktop Gateway Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/)
- [IronRDP](https://github.com/Devolutions/IronRDP) - Rust RDP implementation
- [CyberArk Documentation](https://docs.cyberark.com/)
