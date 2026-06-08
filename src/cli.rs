//! Command-line surface. `reo` with no subcommand opens the interactive shell;
//! the subcommands mirror the natural-language actions so power users can script
//! REO without entering the REPL.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "reo",
    version,
    about = "A local AI security engineer that lives in your terminal. Never phones home.",
    long_about = "REO is a privacy-first, terminal-native security agent. By default it is \
                  air-gapped: no telemetry, no analytics, no cloud. Run `reo` to drop into the \
                  interactive shell, or use a subcommand directly."
)]
pub struct Cli {
    /// Enable cloud model fallback for THIS session only. REO will tell you
    /// exactly what would be transmitted before sending anything.
    #[arg(long, global = true)]
    pub cloud: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a full system scan (processes, network, persistence, scheduled tasks).
    Scan {
        /// Skip the slower sections (scheduled tasks, deep persistence sweep).
        #[arg(long)]
        quick: bool,
    },
    /// Map active network connections and flag suspicious destinations.
    Network,
    /// Behavioral analysis over local telemetry (Pro).
    Investigate,
    /// Harden the machine: close risky ports, tighten firewall, disable services.
    Lockdown {
        /// Actually apply changes. Without this flag, lockdown is a dry run.
        #[arg(long)]
        apply: bool,
    },
    /// Explain why the machine is slow and offer to fix the top causes.
    Slow,
    /// Shrink files locally (free, no account). PNGs lossless; others gzipped.
    Shrink {
        /// Files to shrink.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Scan locally for exposed secrets and personal info (Premium).
    Pii,
    /// Identity protection services: insurance, info removal (Advanced).
    Protect,
    /// Show pricing tiers.
    Plans,
    /// Buy a plan. Opens a Stripe checkout link in your browser.
    Upgrade {
        /// Plan to buy: basic, premium, or advanced. Omit to choose interactively.
        #[arg(long)]
        plan: Option<String>,
    },
    /// Extend an existing paid license.
    Renew,
    /// Show license, privacy posture, and local model status.
    Status,
}
