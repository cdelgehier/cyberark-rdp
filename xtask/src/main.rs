#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use anyhow::Result;
use xshell::{Shell, cmd};

const CARGO: &str = env!("CARGO");

fn main() -> Result<()> {
    let task = std::env::args().nth(1);

    match task.as_deref() {
        Some("ci") => ci(),
        Some("fmt") => fmt(),
        Some("clippy") => clippy(),
        Some("test") => test(),
        Some("build") => build(),
        Some("doc") => doc(),
        _ => {
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    eprintln!("Usage: cargo xtask <TASK>");
    eprintln!();
    eprintln!("Tasks:");
    eprintln!("  ci       Run all CI checks (fmt, clippy, test, build, doc)");
    eprintln!("  fmt      Check code formatting");
    eprintln!("  clippy   Run clippy lints");
    eprintln!("  test     Run tests");
    eprintln!("  build    Build release binary");
    eprintln!("  doc      Build documentation");
}

fn ci() -> Result<()> {
    println!("🚀 Running CI checks...\n");

    fmt()?;
    clippy()?;
    test()?;
    build()?;
    doc()?;

    println!("\n🎉 All CI checks passed!");
    Ok(())
}

fn fmt() -> Result<()> {
    println!("📝 Checking formatting...");
    let sh = Shell::new()?;

    let output = cmd!(sh, "{CARGO} fmt --all -- --check")
        .ignore_status()
        .output()?;

    if !output.status.success() {
        anyhow::bail!("Bad formatting, please run 'cargo fmt --all'");
    }

    println!("✅ Format check passed\n");
    Ok(())
}

fn clippy() -> Result<()> {
    println!("🔍 Running clippy...");
    let sh = Shell::new()?;

    cmd!(
        sh,
        "{CARGO} clippy --all-targets --all-features -- -D warnings"
    )
    .run()?;

    println!("✅ Clippy passed\n");
    Ok(())
}

fn test() -> Result<()> {
    println!("🧪 Running tests...");
    let sh = Shell::new()?;

    cmd!(sh, "{CARGO} test --all-features").run()?;

    println!("✅ Tests passed\n");
    Ok(())
}

fn build() -> Result<()> {
    println!("🔨 Building release...");
    let sh = Shell::new()?;

    cmd!(sh, "{CARGO} build --release").run()?;

    println!("✅ Release build passed\n");
    Ok(())
}

fn doc() -> Result<()> {
    println!("📚 Building documentation...");
    let sh = Shell::new()?;

    cmd!(sh, "{CARGO} doc --no-deps --all-features").run()?;

    println!("✅ Documentation build passed\n");
    Ok(())
}
