mod config;
mod connection;
mod rdp_parser;
mod sia;
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

fn prompt_password(username: &str) -> Result<String> {
    // Try native dialog first (works great on macOS)
    let _ = rfd::MessageDialog::new()
        .set_title("CyberArk RDP - Password")
        .set_description(format!(
            "Enter the RDP password found on CyberArk to log in as user {}.",
            username
        ))
        .set_level(rfd::MessageLevel::Info)
        .show();

    // rfd doesn't have a password input dialog, fall back to terminal
    // On macOS we could use osascript, or just use rpassword for terminal input
    eprint!("Password for {}: ", username);
    let password = rpassword::read_password().context("failed to read password")?;

    if password.is_empty() {
        bail!("empty password");
    }

    Ok(password)
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
    let config = config::Config::load()?;
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

    // Get password
    let password = match cli.password {
        Some(p) => p,
        None => prompt_password(&username)?,
    };

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

    window_result
}
