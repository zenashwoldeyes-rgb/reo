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
    /// Shrink files/folders locally (free), or `--all` to optimize images computer-wide.
    Shrink {
        /// Files or folders to shrink. Omit when using --all.
        files: Vec<PathBuf>,
        /// Losslessly optimize every image across your computer (Pictures, Desktop, Downloads, Documents).
        #[arg(long)]
        all: bool,
    },
    /// Free up disk space by clearing temporary files (shows what first).
    Clean {
        /// Delete without asking for confirmation first.
        #[arg(long)]
        apply: bool,
    },
    /// Find files in your folders by describing them in plain English.
    Find {
        /// What to look for, e.g. `reo find my vacation photos`.
        #[arg(required = true)]
        query: Vec<String>,
    },
    /// Show the biggest files eating your disk space (read-only).
    Space,
    /// On-device behavioral ransomware detection (analyzes file content, all local).
    Detect {
        /// Folder to scan. Omit to sweep your Desktop/Documents/Downloads/Pictures.
        path: Option<String>,
    },
    /// Real-time ransomware protection — watch for active encryption and alert (Ctrl-C to stop).
    Watch {
        /// Folder to watch. Omit to watch your Desktop/Documents/Downloads/Pictures.
        path: Option<String>,
        /// On a detected attack, automatically terminate the responsible process (best run elevated).
        #[arg(long)]
        respond: bool,
    },
    /// [Enterprise] Manage cloud infrastructure by chat: deploy, scale, secure, optimize.
    Infra {
        /// What to do, e.g. `reo infra deploy a postgres database in canada`.
        #[arg(required = true)]
        request: Vec<String>,
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
    /// Activate a license token you received after purchase.
    Activate {
        /// The signed token (starts with `REO1.`). Omit to be prompted.
        token: Option<String>,
    },
    /// Extend an existing paid license.
    Renew,
    /// Show license, privacy posture, and local model status.
    Status,

    /// [seller] Generate a fresh ed25519 license keypair.
    #[command(hide = true)]
    Keygen,
    /// [seller] Mint a signed license token (needs $REO_SIGNING_KEY).
    #[command(hide = true)]
    Issue {
        /// Tier to grant: basic, premium, or advanced.
        #[arg(long)]
        plan: String,
        /// Who the license is for (customer email or Stripe customer id).
        #[arg(long)]
        email: String,
        /// License term in years.
        #[arg(long, default_value_t = 1)]
        years: i64,
    },
}
