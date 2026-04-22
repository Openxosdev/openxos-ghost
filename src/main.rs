mod core;
mod net;
mod output;
mod web;

use anyhow::anyhow;
use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser)]
#[command(
    name = "ghost",
    about = "openxos-ghost — low-noise evasion-aware security probe",
    long_about = "Authorized security research tool. Surfaces findings that standard scanners\nmiss due to WAF/IDS detection. Always use on authorized targets only.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Confirm you have explicit authorization to test this target
    #[arg(long, global = true)]
    authorized: bool,

    /// Evasion profile: slow | medium | aggressive
    #[arg(long, global = true, default_value = "slow")]
    profile: String,

    /// Output format: json | markdown | both
    #[arg(long, global = true, default_value = "json")]
    format: String,

    /// Output file path (default: stdout)
    #[arg(long, global = true)]
    output: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Probe web application targets through WAF/security controls
    Web {
        /// Target URL (e.g. https://example.com)
        #[arg(short, long)]
        target: String,

        /// Specific path to probe (e.g. /admin)
        #[arg(short, long)]
        path: Option<String>,
    },

    /// Probe network/infrastructure targets through IDS/firewall
    Net {
        /// Target IP or hostname
        #[arg(short, long)]
        target: String,

        /// Port range (e.g. 80,443 or 1-1024)
        #[arg(short, long, default_value = "top100")]
        ports: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Err(err) = validate_authorization(cli.authorized) {
        eprintln!("{} {}", "ERROR:".red().bold(), err);
        std::process::exit(1);
    }

    print_banner();

    let profile = core::profile::load(&cli.profile)?;

    match cli.command {
        Commands::Web { target, path } => {
            println!("{} Web mode → {}", ">>".cyan().bold(), target.yellow());
            let results = web::probe::run(&target, path.as_deref(), &profile).await?;
            output::render::write(&results, &cli.format, cli.output.as_deref())?;
        }
        Commands::Net { target, ports } => {
            println!("{} Net mode → {}", ">>".cyan().bold(), target.yellow());
            let results = net::scan::run(&target, &ports, &profile).await?;
            output::render::write(&results, &cli.format, cli.output.as_deref())?;
        }
    }

    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        r#"
  ██████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
▒██    ▒ ▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
░ ▓██▄   ▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
  ▒   ██▒░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
▒██████▒▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
░ ░▒  ░ ░ ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░
░  ░  ░   ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░
      ░   ░  ░  ░    ░ ░        ░
    "#
        .cyan()
    );
    println!(
        "  {} — authorized targets only\n",
        "openxos-ghost v0.1.0".bold()
    );
}

fn validate_authorization(authorized: bool) -> anyhow::Result<()> {
    if authorized {
        Ok(())
    } else {
        Err(anyhow!(
            "--authorized flag required. Only test targets you have explicit permission to probe."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_authorization, Cli};
    use clap::Parser;

    #[test]
    fn cli_parses_global_flags_before_subcommand() {
        let cli = Cli::try_parse_from([
            "ghost",
            "--authorized",
            "web",
            "--target",
            "https://example.com",
        ])
        .expect("cli should parse with global flag before subcommand");
        assert!(cli.authorized);
    }

    #[test]
    fn cli_parses_global_flags_after_subcommand() {
        let cli = Cli::try_parse_from(["ghost", "net", "--target", "127.0.0.1", "--authorized"])
            .expect("cli should parse with global flag after subcommand");
        assert!(cli.authorized);
    }

    #[test]
    fn authorization_gate_rejects_missing_flag() {
        let err = validate_authorization(false).expect_err("missing --authorized must fail");
        assert!(err.to_string().contains("--authorized"));
    }
}
