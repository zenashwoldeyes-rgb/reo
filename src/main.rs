//! REO — a local AI security engineer that lives in your terminal.
//!
//! Privacy is the architecture, not a feature: by default REO never opens a
//! network socket. All inference is local, all telemetry stays on the machine.
//! The only time the network is touched is an explicit `reo upgrade` (to open a
//! Stripe checkout link) or a session the user explicitly starts with `--cloud`.

mod cli;
mod commands;
mod config;
mod crypto;
mod detect;
mod housekeeping;
mod infra;
mod intent;
mod license;
mod model;
mod scan;
mod shell;
mod shrink;
mod ui;

use clap::Parser;
use cli::{Cli, Command};

/// Crate-wide fallible result. Boxed errors keep the surface small for a CLI.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() {
    let cli = Cli::parse();

    // The privacy posture for this invocation. Air-gapped unless the user
    // explicitly opted into cloud fallback for the session.
    let mut ctx = config::Context::load(cli.cloud);

    let result = match cli.command {
        Some(Command::Scan { quick }) => commands::run_scan(&mut ctx, quick),
        Some(Command::Network) => commands::run_network(&mut ctx),
        Some(Command::Investigate) => commands::run_investigate(&mut ctx),
        Some(Command::Lockdown { apply }) => commands::run_lockdown(&mut ctx, apply),
        Some(Command::Slow) => commands::run_slow(&mut ctx),
        Some(Command::Shrink { files, all }) => commands::run_shrink(&files, all),
        Some(Command::Clean { apply }) => commands::run_clean(apply),
        Some(Command::Find { query }) => commands::run_find(&query.join(" ")),
        Some(Command::Space) => commands::run_space(),
        Some(Command::Detect { path }) => commands::run_detect(&mut ctx, path.as_deref()),
        Some(Command::Watch { path, respond }) => commands::run_watch(&mut ctx, path.as_deref(), respond),
        Some(Command::Service { action }) => commands::run_service(&mut ctx, &action),
        Some(Command::Infra { request, apply, local }) => commands::run_infra(&mut ctx, &request.join(" "), apply, local),
        Some(Command::Pii) => commands::run_pii(&mut ctx),
        Some(Command::Protect) => commands::run_protect(&mut ctx),
        Some(Command::Plans) => {
            commands::print_plans();
            Ok(())
        }
        Some(Command::Upgrade { plan }) => commands::run_upgrade(&mut ctx, plan),
        Some(Command::Activate { token }) => commands::run_activate(&mut ctx, token),
        Some(Command::Logout) => commands::run_logout(&mut ctx),
        Some(Command::Renew) => commands::run_renew(&mut ctx),
        Some(Command::Status) => commands::run_status(&mut ctx),
        Some(Command::Keygen) => commands::run_keygen(),
        Some(Command::Issue { plan, email, years }) => commands::run_issue(&plan, &email, years),
        // No subcommand: drop into the persistent secure REPL. The terminal is
        // the product.
        None => shell::run(&mut ctx),
    };

    if let Err(e) = result {
        ui::error(&format!("{e}"));
        std::process::exit(1);
    }
}
