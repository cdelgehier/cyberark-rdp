mod config;
mod connection;
mod rdp_parser;
mod sia;
mod ui;
mod window;

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cyberark-rdp",
    about = "Native macOS RDP client for CyberArk Privilege Cloud",
    version
)]
struct Cli {
    /// Path to the .rdp file downloaded from CyberArk
    rdp_file: PathBuf,

    /// Override username (otherwise read from .rdp file)
    #[arg(short, long)]
    username: Option<String>,

    /// Password (if not provided, a dialog will prompt for it)
    #[arg(short, long)]
    password: Option<String>,

    /// Override desktop width
    #[arg(long)]
    width: Option<u16>,

    /// Override desktop height
    #[arg(long)]
    height: Option<u16>,

    /// Print parsed RDP file and exit (debug)
    #[arg(long)]
    dump_rdp: bool,
}

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Install rustls crypto provider (required for TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;

    let cli = Cli::parse();

    // Load config
    let mut config = config::Config::load()?;
    tracing::debug!("Config: {:?}", config);

    // Parse RDP file
    let rdp_file = rdp_parser::RdpFile::parse(&cli.rdp_file)
        .with_context(|| format!("failed to parse RDP file: {}", cli.rdp_file.display()))?;

    if cli.dump_rdp {
        println!("Parsed RDP file:");
        for (key, value) in rdp_file.entries() {
            println!("  {} = {:?}", key, value);
        }
        return Ok(());
    }

    // Determine username (from RDP file or CLI override)
    let username = if let Some(ref u) = cli.username {
        u.clone()
    } else if let Some(u) = rdp_file.username() {
        u.to_string()
    } else {
        bail!("no username found in .rdp file and --username not provided");
    };

    // Get password and config - either from CLI or dialog
    let (password, resolution, _clipboard, _map_drives, burn_after_reading) = match cli.password {
        Some(p) => {
            // CLI password: load preferences from config
            let config = config::Config::load().unwrap_or_default();
            (
                p,
                config.preferences.resolution.clone(),
                config.preferences.clipboard,
                config.preferences.map_drives,
                false,
            )
        }
        None => {
            // Show config dialog
            let conn_config = ui::show_config_dialog(&cli.rdp_file, None)?;

            match conn_config {
                Some(cfg) => {
                    // Save user preferences
                    let mut config = config::Config::load().unwrap_or_default();
                    config.preferences.resolution = cfg.resolution.clone();
                    config.preferences.clipboard = cfg.clipboard;
                    config.preferences.map_drives = cfg.map_drives;
                    config.preferences.burn_after_reading = cfg.burn_after_reading;

                    if let Err(e) = config.save() {
                        tracing::warn!("Failed to save config: {}", e);
                    }

                    (
                        cfg.password,
                        cfg.resolution,
                        cfg.clipboard,
                        cfg.map_drives,
                        cfg.burn_after_reading,
                    )
                }
                None => {
                    tracing::info!("User cancelled connection");
                    return Ok(());
                }
            }
        }
    };

    // Parse and apply resolution from user preferences
    if let Some((width, height)) = config::Config::parse_resolution(&resolution) {
        config.default_width = width;
        config.default_height = height;
        tracing::info!("Using resolution: {}x{}", width, height);
    }

    tracing::info!(
        "Connecting as {} to {}:{}",
        username,
        rdp_file.hostname().unwrap_or_default(),
        rdp_file.port()
    );

    // Connect
    let session = connection::connect(&rdp_file, &config, &username, &password)?;

    tracing::info!("✅ RDP connection established successfully!");
    tracing::info!(
        "Desktop size: {}x{}",
        session.desktop_size.width,
        session.desktop_size.height
    );

    println!("\n✅ Connection established successfully!");
    println!(
        "   Server: {}:{}",
        rdp_file.hostname().unwrap_or_default(),
        rdp_file.port()
    );
    println!("   User: {}", username);
    println!(
        "   Desktop: {}x{}",
        session.desktop_size.width, session.desktop_size.height
    );
    println!("\n🚀 Starting interactive RDP session...\n");

    // Create communication channels
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    let (update_tx, update_rx) = std::sync::mpsc::channel();

    // Save desktop size before moving session
    let desktop_size = session.desktop_size;

    // Spawn RDP network thread
    let rdp_thread = std::thread::spawn(move || {
        if let Err(e) = connection::rdp_network_loop(session, input_rx, update_tx) {
            tracing::error!("RDP thread error: {}", e);
        }
        tracing::info!("RDP thread terminated");
    });

    // Run window on main thread (required for macOS)
    let window_result = window::run_window(desktop_size, input_tx, update_rx);

    // Wait for RDP thread to finish
    if let Err(e) = rdp_thread.join() {
        tracing::error!("Failed to join RDP thread: {:?}", e);
    }

    // Burn after reading: delete .rdp file if requested
    if burn_after_reading {
        match std::fs::remove_file(&cli.rdp_file) {
            Ok(_) => {
                tracing::info!("🔥 Deleted .rdp file: {}", cli.rdp_file.display());
                println!("🔥 RDP file deleted (burn after reading)");
            }
            Err(e) => {
                tracing::warn!("Failed to delete .rdp file: {}", e);
            }
        }
    }

    window_result
}
