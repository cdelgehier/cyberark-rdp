use anyhow::{Context, Result};
use softbuffer::Surface;
use std::num::NonZeroU32;
use std::sync::{Arc, mpsc};
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::{ElementState, MouseButton, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::window::{Window, WindowId};

use crate::connection::{DesktopSize, InputEvent};

/// The main application state
struct RdpApp {
    window: Option<Arc<Window>>,
    surface: Option<Surface<Arc<Window>, Arc<Window>>>,
    desktop_size: DesktopSize,
    /// RGBA framebuffer (will be updated by RDP session)
    framebuffer: Vec<u32>,

    // Communication channels
    input_tx: mpsc::Sender<InputEvent>,
    update_rx: mpsc::Receiver<Vec<u8>>,

    // Mouse state
    mouse_x: u16,
    mouse_y: u16,

    // Performance metrics
    frame_count: u64,
    last_fps_update: std::time::Instant,
    fps: f64,
}

#[allow(dead_code)]
impl RdpApp {
    fn new(
        desktop_size: DesktopSize,
        input_tx: mpsc::Sender<InputEvent>,
        update_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        let pixel_count = desktop_size.width as usize * desktop_size.height as usize;
        Self {
            window: None,
            surface: None,
            desktop_size,
            framebuffer: vec![0xFF000000; pixel_count], // Black with full alpha
            input_tx,
            update_rx,
            mouse_x: 0,
            mouse_y: 0,
            frame_count: 0,
            last_fps_update: std::time::Instant::now(),
            fps: 0.0,
        }
    }

    fn render(&mut self) {
        let Some(surface) = self.surface.as_mut() else {
            return;
        };
        let Some(window) = &self.window else {
            return;
        };

        // Get the physical window size (handles Retina/HiDPI displays)
        let physical_size = window.inner_size();
        let window_width = physical_size.width.max(1);
        let window_height = physical_size.height.max(1);

        // Resize surface to match physical window size
        surface
            .resize(
                NonZeroU32::new(window_width).unwrap(),
                NonZeroU32::new(window_height).unwrap(),
            )
            .expect("failed to resize surface");

        let mut buffer = surface.buffer_mut().expect("failed to get buffer");

        let fb_width = self.desktop_size.width as u32;
        let fb_height = self.desktop_size.height as u32;

        // Calculate scale factors
        let scale_x = window_width as f32 / fb_width as f32;
        let scale_y = window_height as f32 / fb_height as f32;

        // If scales are close to 1.0, do direct copy (no scaling needed)
        if (scale_x - 1.0).abs() < 0.01 && (scale_y - 1.0).abs() < 0.01 {
            if self.framebuffer.len() == (window_width * window_height) as usize {
                buffer.copy_from_slice(&self.framebuffer);
            }
        } else {
            // Scale the framebuffer to fill the window (nearest neighbor)
            for y in 0..window_height {
                for x in 0..window_width {
                    let src_x = ((x as f32 / scale_x) as u32).min(fb_width - 1);
                    let src_y = ((y as f32 / scale_y) as u32).min(fb_height - 1);

                    let src_idx = (src_y * fb_width + src_x) as usize;
                    let dst_idx = (y * window_width + x) as usize;

                    if src_idx < self.framebuffer.len() && dst_idx < buffer.len() {
                        buffer[dst_idx] = self.framebuffer[src_idx];
                    }
                }
            }
        }

        buffer.present().expect("failed to present buffer");
    }

    /// Update a region of the framebuffer with BGRA data from RDP
    pub fn update_framebuffer(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        bgra_data: &[u8],
    ) {
        let stride = self.desktop_size.width as usize;
        for row in 0..height as usize {
            for col in 0..width as usize {
                let src_idx = (row * width as usize + col) * 4;
                if src_idx + 3 >= bgra_data.len() {
                    break;
                }
                let b = bgra_data[src_idx] as u32;
                let g = bgra_data[src_idx + 1] as u32;
                let r = bgra_data[src_idx + 2] as u32;
                // softbuffer format: 0x00RRGGBB
                let pixel = (r << 16) | (g << 8) | b;

                let dst_x = x as usize + col;
                let dst_y = y as usize + row;
                if dst_x < stride && dst_y < self.desktop_size.height as usize {
                    self.framebuffer[dst_y * stride + dst_x] = pixel;
                }
            }
        }
    }
}

/// Convert RGBA data from DecodedImage to softbuffer RGB format
fn rgba_to_rgb(rgba: &[u8]) -> Vec<u32> {
    // DecodedImage gives RGBA, softbuffer wants 0x00RRGGBB
    rgba.chunks_exact(4)
        .map(|pixel| {
            let r = pixel[0] as u32;
            let g = pixel[1] as u32;
            let b = pixel[2] as u32;
            // Skip alpha channel (pixel[3])
            (r << 16) | (g << 8) | b
        })
        .collect()
}

/// Map winit KeyCode to Windows RDP scancode
/// Based on scan code set 1 (XT)
fn map_key_to_scancode(key: &PhysicalKey) -> Option<u16> {
    match key {
        PhysicalKey::Code(code) => match code {
            // Letters (A-Z in QWERTY layout)
            KeyCode::KeyA => Some(0x1E),
            KeyCode::KeyB => Some(0x30),
            KeyCode::KeyC => Some(0x2E),
            KeyCode::KeyD => Some(0x20),
            KeyCode::KeyE => Some(0x12),
            KeyCode::KeyF => Some(0x21),
            KeyCode::KeyG => Some(0x22),
            KeyCode::KeyH => Some(0x23),
            KeyCode::KeyI => Some(0x17),
            KeyCode::KeyJ => Some(0x24),
            KeyCode::KeyK => Some(0x25),
            KeyCode::KeyL => Some(0x26),
            KeyCode::KeyM => Some(0x32),
            KeyCode::KeyN => Some(0x31),
            KeyCode::KeyO => Some(0x18),
            KeyCode::KeyP => Some(0x19),
            KeyCode::KeyQ => Some(0x10),
            KeyCode::KeyR => Some(0x13),
            KeyCode::KeyS => Some(0x1F),
            KeyCode::KeyT => Some(0x14),
            KeyCode::KeyU => Some(0x16),
            KeyCode::KeyV => Some(0x2F),
            KeyCode::KeyW => Some(0x11),
            KeyCode::KeyX => Some(0x2D),
            KeyCode::KeyY => Some(0x15),
            KeyCode::KeyZ => Some(0x2C),

            // Numbers (0-9)
            KeyCode::Digit1 => Some(0x02),
            KeyCode::Digit2 => Some(0x03),
            KeyCode::Digit3 => Some(0x04),
            KeyCode::Digit4 => Some(0x05),
            KeyCode::Digit5 => Some(0x06),
            KeyCode::Digit6 => Some(0x07),
            KeyCode::Digit7 => Some(0x08),
            KeyCode::Digit8 => Some(0x09),
            KeyCode::Digit9 => Some(0x0A),
            KeyCode::Digit0 => Some(0x0B),

            // Special keys
            KeyCode::Enter => Some(0x1C),
            KeyCode::Escape => Some(0x01),
            KeyCode::Backspace => Some(0x0E),
            KeyCode::Tab => Some(0x0F),
            KeyCode::Space => Some(0x39),
            KeyCode::Minus => Some(0x0C),
            KeyCode::Equal => Some(0x0D),
            KeyCode::BracketLeft => Some(0x1A),
            KeyCode::BracketRight => Some(0x1B),
            KeyCode::Backslash => Some(0x2B),
            KeyCode::Semicolon => Some(0x27),
            KeyCode::Quote => Some(0x28),
            KeyCode::Backquote => Some(0x29),
            KeyCode::Comma => Some(0x33),
            KeyCode::Period => Some(0x34),
            KeyCode::Slash => Some(0x35),
            KeyCode::CapsLock => Some(0x3A),

            // Function keys
            KeyCode::F1 => Some(0x3B),
            KeyCode::F2 => Some(0x3C),
            KeyCode::F3 => Some(0x3D),
            KeyCode::F4 => Some(0x3E),
            KeyCode::F5 => Some(0x3F),
            KeyCode::F6 => Some(0x40),
            KeyCode::F7 => Some(0x41),
            KeyCode::F8 => Some(0x42),
            KeyCode::F9 => Some(0x43),
            KeyCode::F10 => Some(0x44),
            KeyCode::F11 => Some(0x57),
            KeyCode::F12 => Some(0x58),

            // Modifiers
            KeyCode::ShiftLeft => Some(0x2A),
            KeyCode::ShiftRight => Some(0x36),
            KeyCode::ControlLeft => Some(0x1D),
            KeyCode::ControlRight => Some(0xE01D), // Extended key
            KeyCode::AltLeft => Some(0x38),
            KeyCode::AltRight => Some(0xE038),   // Extended key
            KeyCode::SuperLeft => Some(0xE05B),  // Windows key
            KeyCode::SuperRight => Some(0xE05C), // Windows key

            // Arrow keys (extended)
            KeyCode::ArrowUp => Some(0xE048),
            KeyCode::ArrowDown => Some(0xE050),
            KeyCode::ArrowLeft => Some(0xE04B),
            KeyCode::ArrowRight => Some(0xE04D),

            // Navigation keys (extended)
            KeyCode::Insert => Some(0xE052),
            KeyCode::Delete => Some(0xE053),
            KeyCode::Home => Some(0xE047),
            KeyCode::End => Some(0xE04F),
            KeyCode::PageUp => Some(0xE049),
            KeyCode::PageDown => Some(0xE051),

            // Numpad
            KeyCode::NumLock => Some(0x45),
            KeyCode::Numpad0 => Some(0x52),
            KeyCode::Numpad1 => Some(0x4F),
            KeyCode::Numpad2 => Some(0x50),
            KeyCode::Numpad3 => Some(0x51),
            KeyCode::Numpad4 => Some(0x4B),
            KeyCode::Numpad5 => Some(0x4C),
            KeyCode::Numpad6 => Some(0x4D),
            KeyCode::Numpad7 => Some(0x47),
            KeyCode::Numpad8 => Some(0x48),
            KeyCode::Numpad9 => Some(0x49),
            KeyCode::NumpadAdd => Some(0x4E),
            KeyCode::NumpadSubtract => Some(0x4A),
            KeyCode::NumpadMultiply => Some(0x37),
            KeyCode::NumpadDivide => Some(0xE035),
            KeyCode::NumpadDecimal => Some(0x53),
            KeyCode::NumpadEnter => Some(0xE01C),

            _ => {
                tracing::debug!("Unmapped key: {:?}", code);
                None
            }
        },
        _ => None,
    }
}

impl ApplicationHandler for RdpApp {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }

        let size = LogicalSize::new(
            self.desktop_size.width as f64,
            self.desktop_size.height as f64,
        );

        let attrs = Window::default_attributes()
            .with_title("CyberArk RDP")
            .with_inner_size(size)
            .with_resizable(false); // Disable window resizing

        let window = Arc::new(
            event_loop
                .create_window(attrs)
                .expect("failed to create window"),
        );

        let context =
            softbuffer::Context::new(window.clone()).expect("failed to create softbuffer context");
        let surface = Surface::new(&context, window.clone()).expect("failed to create surface");

        self.window = Some(window);
        self.surface = Some(surface);

        // Set up continuous redraw
        event_loop.set_control_flow(ControlFlow::Poll);

        // Initial render (black screen)
        self.render();
    }

    fn new_events(&mut self, _event_loop: &ActiveEventLoop, _cause: winit::event::StartCause) {
        // Request redraw on every event loop iteration
        if let Some(window) = &self.window {
            window.request_redraw();
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => {
                tracing::info!("Window closed");
                let _ = self.input_tx.send(InputEvent::Shutdown);
                event_loop.exit();
            }

            WindowEvent::RedrawRequested => {
                // Check for framebuffer updates from RDP thread
                let mut received_update = false;
                loop {
                    match self.update_rx.try_recv() {
                        Ok(rgba_data) => {
                            tracing::debug!(
                                "Received framebuffer update: {} bytes",
                                rgba_data.len()
                            );
                            self.framebuffer = rgba_to_rgb(&rgba_data);
                            received_update = true;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            // RDP thread has terminated, close the window
                            tracing::info!("RDP connection closed, shutting down window");
                            event_loop.exit();
                            return;
                        }
                    }
                }
                if received_update {
                    tracing::debug!(
                        "Framebuffer updated, rendering {} pixels",
                        self.framebuffer.len()
                    );
                }
                self.render();

                // Update FPS counter
                self.frame_count += 1;
                let elapsed = self.last_fps_update.elapsed();
                if elapsed.as_secs_f64() >= 1.0 {
                    self.fps = self.frame_count as f64 / elapsed.as_secs_f64();
                    self.frame_count = 0;
                    self.last_fps_update = std::time::Instant::now();

                    // Update window title with FPS
                    if let Some(window) = &self.window {
                        window.set_title(&format!("CyberArk RDP - {:.1} FPS", self.fps));
                    }
                }
            }

            WindowEvent::KeyboardInput { event, .. } => {
                use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};

                // Map the key to a Windows scancode
                if let Some(scancode) = map_key_to_scancode(&event.physical_key) {
                    // Check if it's an extended key (scancode > 0xFF)
                    let is_extended = scancode > 0xFF;
                    let base_scancode = if is_extended {
                        (scancode & 0xFF) as u8
                    } else {
                        scancode as u8
                    };

                    // Build flags
                    let mut flags = KeyboardFlags::empty();

                    if event.state == ElementState::Released {
                        flags |= KeyboardFlags::RELEASE;
                    }

                    if is_extended {
                        flags |= KeyboardFlags::EXTENDED;
                    }

                    let kbd_event = FastPathInputEvent::KeyboardEvent(flags, base_scancode);

                    tracing::trace!(
                        "Sending keyboard event: scancode={:02X}, flags={:?}",
                        base_scancode,
                        flags
                    );
                    let _ = self.input_tx.send(InputEvent::Keyboard(kbd_event));
                } else {
                    tracing::trace!("Key event ignored: {:?}", event.physical_key);
                }
            }

            WindowEvent::CursorMoved { position, .. } => {
                use ironrdp_pdu::input::fast_path::FastPathInputEvent;
                use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};

                // Scale mouse coordinates to match RDP desktop size
                if let Some(window) = &self.window {
                    let physical_size = window.inner_size();
                    let scale_x = self.desktop_size.width as f32 / physical_size.width as f32;
                    let scale_y = self.desktop_size.height as f32 / physical_size.height as f32;

                    self.mouse_x = (position.x as f32 * scale_x) as u16;
                    self.mouse_y = (position.y as f32 * scale_y) as u16;

                    // Clamp to desktop bounds
                    self.mouse_x = self.mouse_x.min(self.desktop_size.width - 1);
                    self.mouse_y = self.mouse_y.min(self.desktop_size.height - 1);

                    let evt = FastPathInputEvent::MouseEvent(MousePdu {
                        flags: PointerFlags::MOVE,
                        number_of_wheel_rotation_units: 0,
                        x_position: self.mouse_x,
                        y_position: self.mouse_y,
                    });

                    let _ = self.input_tx.send(InputEvent::Mouse(evt));
                }
            }

            WindowEvent::MouseInput { state, button, .. } => {
                use ironrdp_pdu::input::fast_path::FastPathInputEvent;
                use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};

                let mut flags = match button {
                    MouseButton::Left => PointerFlags::LEFT_BUTTON,
                    MouseButton::Right => PointerFlags::RIGHT_BUTTON,
                    MouseButton::Middle => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                    _ => return,
                };

                if state == ElementState::Pressed {
                    flags |= PointerFlags::DOWN;
                }

                let evt = FastPathInputEvent::MouseEvent(MousePdu {
                    flags,
                    number_of_wheel_rotation_units: 0,
                    x_position: self.mouse_x,
                    y_position: self.mouse_y,
                });

                let _ = self.input_tx.send(InputEvent::Mouse(evt));
            }

            _ => {}
        }
    }
}

/// Create and run the native window with the RDP session
pub fn run_window(
    desktop_size: DesktopSize,
    input_tx: mpsc::Sender<InputEvent>,
    update_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let event_loop = EventLoop::new().context("failed to create event loop")?;
    let mut app = RdpApp::new(desktop_size, input_tx, update_rx);

    event_loop.run_app(&mut app).context("event loop error")?;

    Ok(())
}
