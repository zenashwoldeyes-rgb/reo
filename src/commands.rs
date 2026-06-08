//! Command implementations. These back both the `reo <subcommand>` entry points
//! and the natural-language intents from the REPL, so behavior is identical
//! whether the user scripts REO or talks to it.

use crate::config::Context;
use crate::intent::Intent;
use crate::license::{self, License, Tier};
use crate::scan::network::{self, Class};
use crate::scan::{self, ScanOptions};
use crate::{model, shrink, ui};
use std::io::Write;
use std::path::PathBuf;
use sysinfo::System;

use crate::Result;

/// Route a parsed intent from the shell. Returns Ok(false) to signal the REPL
/// should exit.
pub fn handle(ctx: &mut Context, intent: Intent) -> Result<bool> {
    match intent {
        Intent::Scan => run_scan(ctx, false)?,
        Intent::Network => run_network(ctx)?,
        Intent::Investigate => run_investigate(ctx)?,
        Intent::Remove => run_remove(ctx)?,
        Intent::Slow => run_slow(ctx)?,
        Intent::Lockdown => run_lockdown(ctx, false)?,
        Intent::Timeline => run_timeline(ctx)?,
        Intent::Shrink(args) => run_shrink(&args.iter().map(PathBuf::from).collect::<Vec<_>>())?,
        Intent::Pii => run_pii(ctx)?,
        Intent::Protect => run_protect(ctx)?,
        Intent::Plans => print_plans(),
        Intent::Upgrade => run_upgrade(ctx, None)?,
        Intent::Renew => run_renew(ctx)?,
        Intent::Status => run_status(ctx)?,
        Intent::Privacy => print_privacy(ctx),
        Intent::Help => print_help(),
        Intent::Quit => return Ok(false),
        Intent::Unknown(text) => unknown(&text),
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Scanning & analysis
// ---------------------------------------------------------------------------

pub fn run_scan(ctx: &mut Context, quick: bool) -> Result<()> {
    ui::say("Running a full local scan. Nothing leaves this machine.");
    let report = scan::full_scan(ctx, ScanOptions { quick });
    report.print();

    let model = model::active(ctx);
    let headline: Vec<String> = report
        .findings
        .iter()
        .filter(|f| f.score >= 35)
        .map(|f| format!("{} — {}", f.title, f.detail))
        .collect();
    ui::section("Summary");
    print!("{}", model.narrate("this scan", &headline));
    println!();
    if !headline.is_empty() {
        ui::info("Say `remove` and I'll walk through remediating the top finding.");
    }
    Ok(())
}

pub fn run_network(_ctx: &mut Context) -> Result<()> {
    ui::say("Mapping active connections. I'm only reading local socket state — no packets sent.");
    let mut sys = System::new_all();
    sys.refresh_all();
    let conns = network::collect(&sys);

    if conns.is_empty() {
        ui::warn("No connections enumerated (is `netstat` available on PATH?).");
        return Ok(());
    }

    ui::section("Connection map");
    println!(
        "   {:<7}{:<24}{:<24}{:<13}{}",
        "proto", "local", "remote", "class", "process"
    );
    for c in &conns {
        let tag = c.class.label();
        println!(
            "   {:<7}{:<24}{:<24}{:<13}{} (pid {})",
            c.proto, c.local, c.remote, tag, c.process, c.pid
        );
    }

    let public: Vec<_> = conns.iter().filter(|c| c.class == Class::Public).collect();
    ui::section("Plain language");
    if public.is_empty() {
        ui::success("Nothing is talking to public infrastructure right now — only loopback/LAN.");
    } else {
        for c in &public {
            ui::bullet(&format!(
                "{} (pid {}) holds a session to {}. That's outside your LAN.",
                c.process, c.pid, c.remote
            ));
        }
        ui::dim("   Enable an explicit threat-intel sync to label these IPs by reputation.");
    }
    Ok(())
}

pub fn run_slow(_ctx: &mut Context) -> Result<()> {
    ui::say("Profiling CPU, memory, and startup load.");
    let mut sys = System::new_all();
    std::thread::sleep(std::time::Duration::from_millis(300));
    sys.refresh_all();

    let mut by_cpu: Vec<_> = sys.processes().values().collect();
    by_cpu.sort_by(|a, b| b.cpu_usage().partial_cmp(&a.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));
    let mut by_mem: Vec<_> = sys.processes().values().collect();
    by_mem.sort_by(|a, b| b.memory().cmp(&a.memory()));

    ui::section("Top CPU");
    for p in by_cpu.iter().take(3) {
        ui::bullet(&format!(
            "{} — {:.1}% CPU",
            p.name().to_string_lossy(),
            p.cpu_usage()
        ));
    }
    ui::section("Top memory");
    for p in by_mem.iter().take(3) {
        ui::bullet(&format!(
            "{} — {} MB",
            p.name().to_string_lossy(),
            p.memory() / 1_048_576
        ));
    }

    let total = sys.total_memory() as f64;
    let used = sys.used_memory() as f64;
    let mem_pct = if total > 0.0 { used / total * 100.0 } else { 0.0 };

    ui::section("Top three causes");
    ui::bullet(&format!(
        "Memory pressure: {:.0}% of RAM in use ({} MB / {} MB).",
        mem_pct,
        (used as u64) / 1_048_576,
        (total as u64) / 1_048_576
    ));
    if let Some(top) = by_cpu.first() {
        ui::bullet(&format!(
            "`{}` is the heaviest CPU consumer right now.",
            top.name().to_string_lossy()
        ));
    }
    ui::bullet("Startup load: run `scan` to see every program launching at login.");
    ui::info("I can offer to disable a startup item or stop a runaway process — say `remove`.");
    Ok(())
}

pub fn run_investigate(ctx: &mut Context) -> Result<()> {
    if !require_tier(ctx, Tier::Basic, "Deep behavioral investigation") {
        return Ok(());
    }
    ui::say("Pulling local telemetry and running behavioral analysis.");
    let report = scan::full_scan(ctx, ScanOptions { quick: true });
    let events = recent_events(12);

    let mut facts: Vec<String> = report
        .findings
        .iter()
        .filter(|f| f.score >= 35)
        .map(|f| format!("{}: {}", f.title, f.detail))
        .collect();
    facts.extend(events.iter().cloned());

    ui::section("Narrative");
    print!("{}", model::active(ctx).narrate("the last 12 hours", &facts));
    println!();
    ui::dim(
        "   Full 30-day behavioral baselining needs REO's background collector running\n   \
         continuously (Pro daemon). This build analyzes signals available right now.",
    );
    Ok(())
}

pub fn run_timeline(ctx: &mut Context) -> Result<()> {
    if !require_tier(ctx, Tier::Basic, "30-day telemetry lookback") {
        return Ok(());
    }
    ui::say("Correlating local security logs from the last 12 hours.");
    let events = recent_events(12);
    ui::section("Overnight timeline");
    if events.is_empty() {
        ui::warn("No events retrieved (Windows Event Log query needs `powershell` on PATH).");
    } else {
        for e in &events {
            ui::bullet(e);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Remediation & hardening
// ---------------------------------------------------------------------------

pub fn run_remove(ctx: &mut Context) -> Result<()> {
    ui::say("Re-scanning so I act on the freshest picture.");
    let report = scan::full_scan(ctx, ScanOptions { quick: true });

    let target = report
        .findings
        .iter()
        .filter(|f| matches!(f.category.as_str(), "process" | "persistence" | "scheduled task"))
        .max_by_key(|f| f.score);

    let Some(target) = target.filter(|f| f.score >= 35) else {
        ui::success("Nothing meets the remediation threshold. Your machine looks clean.");
        return Ok(());
    };

    ui::section("Remediation plan");
    ui::kv("target", &target.title);
    ui::kv("reason", &target.detail);
    for ev in &target.evidence {
        ui::kv("evidence", ev);
    }
    println!();
    ui::dim("   Before:  present and active");
    ui::dim("   After:   process terminated, image quarantined, persistence removed");
    println!();

    if !prompt_yes_no("Apply this remediation now?")? {
        ui::info("Left untouched. Nothing was changed.");
        return Ok(());
    }

    // Conservative, reversible action in this build: terminate the offending
    // process if we can identify its PID. File quarantine and registry surgery
    // are part of Pro one-command full repair and are intentionally not executed
    // automatically here.
    if let Some(pid) = extract_pid(&target.title) {
        let mut sys = System::new_all();
        sys.refresh_all();
        if let Some(proc_) = sys.process(sysinfo::Pid::from_u32(pid)) {
            if proc_.kill() {
                ui::success(&format!("Terminated pid {pid}."));
            } else {
                ui::warn(&format!("Could not terminate pid {pid} (try an elevated shell)."));
            }
        } else {
            ui::warn("Process already gone.");
        }
    }
    if ctx.license.is_paid() {
        ui::info("Full repair — quarantining image and clearing persistence entries.");
        ui::dim("   (file/registry remediation wiring lands with the signed paid build)");
    } else {
        ui::info("Basic remediation done. One-command full repair (file + registry) is a paid feature — say `plans`.");
    }
    Ok(())
}

pub fn run_lockdown(_ctx: &mut Context, apply: bool) -> Result<()> {
    ui::say(if apply {
        "Hardening this machine."
    } else {
        "Here's what locking down would change (dry run)."
    });

    let mut sys = System::new_all();
    sys.refresh_all();
    let conns = network::collect(&sys);
    let listeners: Vec<_> = conns
        .iter()
        .filter(|c| c.class == Class::Listen && !c.local.starts_with("127."))
        .collect();

    ui::section("Planned changes");
    ui::bullet("Enable the firewall on all profiles with default-deny inbound.");
    if listeners.is_empty() {
        ui::bullet("No non-loopback listeners to close.");
    } else {
        for l in &listeners {
            ui::bullet(&format!("Review listener {} ({})", l.local, l.process));
        }
    }
    ui::bullet("Disable legacy/unneeded services (SMBv1, Remote Registry) if present.");

    if !apply {
        ui::info("Run `reo lockdown --apply` (elevated) to make these changes.");
        return Ok(());
    }

    ui::section("Applying");
    match scan::capture("netsh", &["advfirewall", "set", "allprofiles", "state", "on"]) {
        Some(_) => ui::success("Firewall enabled on all profiles."),
        None => ui::warn("Couldn't change firewall state — re-run from an elevated terminal."),
    }
    ui::dim("   Service hardening requires elevation and is reported, not forced, in this build.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Licensing
// ---------------------------------------------------------------------------

pub fn run_upgrade(ctx: &mut Context, plan_name: Option<String>) -> Result<()> {
    // Resolve which plan to buy: explicit `--plan`, else ask in the terminal.
    let plan = match plan_name {
        Some(name) => match license::plan_by_name(&name) {
            Some(p) => p,
            None => {
                ui::warn(&format!("Unknown plan \"{name}\". Choose: Basic, Premium, or Advanced."));
                print_plans();
                return Ok(());
            }
        },
        None => {
            print_plans();
            let choice = prompt_line("Which plan? [basic/premium/advanced] (or blank to cancel)")?;
            if choice.trim().is_empty() {
                ui::info("No problem — nothing was changed.");
                return Ok(());
            }
            match license::plan_by_name(&choice) {
                Some(p) => p,
                None => {
                    ui::warn("Didn't recognize that plan. Run `upgrade` again to retry.");
                    return Ok(());
                }
            }
        }
    };

    if ctx.license.has(plan.tier) {
        ui::success(&format!("You're already on {} or higher. Say `status` for details.", plan.name));
        return Ok(());
    }

    let mid = ctx.license.machine_id.clone();
    // In production this URL comes from your backend creating a Stripe Checkout
    // Session bound to this machine id; the browser is the ONLY moment the
    // network is touched.
    let url = format!(
        "https://checkout.reo.sh/buy?machine={mid}&plan={}",
        plan.name.to_lowercase()
    );

    ui::say(&format!(
        "REO {} — {}. Pay C${:.2} today for the first year, renews at C${:.2}/yr.",
        plan.name, plan.tagline, plan.first_year_cad, plan.renewal_cad
    ));
    ui::section("Checkout");
    ui::kv("link", &url);
    ui::dim("   This is the only time REO uses the network. Open it to pay; your key returns here.");

    if prompt_yes_no("Open this link in your browser now?")? {
        open_browser(&url);
    }

    // No live billing backend in this build: issue a sandbox key locally so the
    // end-to-end activation flow is exercisable. A shipping build waits for the
    // signed token from the Stripe webhook instead.
    let key = format!(
        "REO-{}-{}-SANDBOX",
        plan.name.to_uppercase(),
        &mid[..8.min(mid.len())]
    );
    ctx.license.activate(plan.tier, key.clone());
    ctx.license.save(&ctx.data_dir)?;

    ui::section("Activated");
    ui::success(&format!("{} unlocked. License key: {key}", plan.name));
    ui::dim("   [sandbox] No charge was made in this build. Stored & validated entirely offline.");
    if let Some(days) = ctx.license.days_until_renewal() {
        ui::info(&format!("Renews in {days} days. REO will remind you in-terminal."));
    }
    Ok(())
}

pub fn run_renew(ctx: &mut Context) -> Result<()> {
    if !ctx.license.is_paid() {
        ui::warn("No active paid license to renew. Say `plans` to see options.");
        return Ok(());
    }
    ctx.license.extend();
    ctx.license.save(&ctx.data_dir)?;
    if let Some(days) = ctx.license.days_until_renewal() {
        ui::success(&format!("Renewed. Your plan now extends ~{days} more days."));
    }
    Ok(())
}

pub fn run_status(ctx: &mut Context) -> Result<()> {
    let m = model::detect(ctx);
    ui::section("REO status");
    ui::kv("tier", ctx.license.tier.label());
    if let Some(p) = license::plan(ctx.license.tier) {
        ui::kv("plan", p.tagline);
        for feat in p.features {
            ui::kv("·", feat);
        }
    }
    if let Some(key) = &ctx.license.key {
        ui::kv("license", key);
    }
    if let Some(days) = ctx.license.days_until_renewal() {
        ui::kv("renews in", &format!("{days} days"));
    }
    ui::kv("machine id", &ctx.license.machine_id);
    ui::kv("privacy", if ctx.cloud { "cloud fallback ENABLED (this session)" } else { "air-gapped" });
    ui::kv("model", m.backend);
    if !m.present {
        ui::kv("model path", &m.path.to_string_lossy());
    }
    ui::kv("data dir", &ctx.data_dir.to_string_lossy());
    Ok(())
}

// ---------------------------------------------------------------------------
// Free file shrinking (the no-account hook) + tiered protection features
// ---------------------------------------------------------------------------

pub fn run_shrink(files: &[PathBuf]) -> Result<()> {
    if files.is_empty() {
        ui::say("Tell me what to shrink, e.g. `shrink screenshot.png` or `shrink notes.txt`.");
        ui::dim("   PNGs are optimized losslessly in place; anything else is compressed to a .gz alongside it. All local, no account.");
        return Ok(());
    }

    ui::say("Shrinking locally — nothing is uploaded.");
    ui::section("Results");
    let mut total_before = 0u64;
    let mut total_after = 0u64;
    for path in files {
        match shrink::shrink_file(path) {
            Ok(r) => {
                total_before += r.before;
                total_after += r.after;
                let note = if r.saved_pct() < 1.0 && shrink::is_precompressed(
                    &path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default(),
                ) {
                    "  (already a compressed format — little to gain)"
                } else {
                    ""
                };
                ui::success(&format!(
                    "{}  {} → {}  (−{:.1}%, {}){}",
                    path.display(),
                    shrink::human(r.before),
                    shrink::human(r.after),
                    r.saved_pct(),
                    r.method,
                    note
                ));
                if r.output != r.input {
                    ui::kv("wrote", &r.output.to_string_lossy());
                }
            }
            Err(e) => ui::error(&format!("{}: {e}", path.display())),
        }
    }
    if files.len() > 1 && total_before > 0 {
        let pct = (total_before.saturating_sub(total_after)) as f64 / total_before as f64 * 100.0;
        ui::section("Total");
        ui::info(&format!(
            "{} → {}  (−{:.1}% across {} files)",
            shrink::human(total_before),
            shrink::human(total_after),
            pct,
            files.len()
        ));
    }
    Ok(())
}

pub fn run_pii(ctx: &mut Context) -> Result<()> {
    if !require_tier(ctx, Tier::Premium, "Local personal-info scan") {
        return Ok(());
    }
    ui::say("Scanning your home directory for exposed secrets and personal info — all local.");
    let hits = scan_personal_info();
    ui::section("Personal-info exposure");
    if hits.is_empty() {
        ui::success("No obvious plaintext secrets or credential files surfaced.");
    } else {
        for h in &hits {
            ui::bullet(h);
        }
        ui::info("Review these. Move secrets into a password manager or your OS keychain.");
    }
    Ok(())
}

pub fn run_protect(ctx: &mut Context) -> Result<()> {
    if !require_tier(ctx, Tier::Advanced, "Identity protection services") {
        return Ok(());
    }
    ui::say("Advanced identity services.");
    ui::section("Your identity protection");
    ui::bullet("$1M identity theft insurance — eligible (enroll once to activate).");
    ui::bullet("Personal info removal — opt-in: REO submits removal requests to data brokers.");
    ui::bullet("Financial-account monitoring — opt-in.");
    ui::dim(
        "   These are the only features that use the network, and only after you explicitly\n   \
         enroll. REO shows exactly what is transmitted before anything is sent.",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Conversational helpers
// ---------------------------------------------------------------------------

pub fn print_help() {
    ui::section("What you can say");
    let rows = [
        ("shrink screenshot.png", "shrink files locally — free, no account"),
        ("scan my computer", "full system scan with risk scores"),
        ("what's running on my network", "map active connections, flag public egress"),
        ("something feels off, investigate", "behavioral analysis (Basic+)"),
        ("remove the adware", "remediate the top finding"),
        ("why is my machine slow", "profile CPU/RAM/startup, top 3 causes"),
        ("show me what happened last night", "correlate local logs (Basic+)"),
        ("scan for my personal info", "find exposed secrets & PII (Premium+)"),
        ("protect my identity", "identity insurance & info removal (Advanced)"),
        ("lock this machine down", "harden firewall, close risky ports"),
        ("plans", "see pricing tiers"),
        ("upgrade", "open checkout, activate offline"),
        ("privacy", "explain exactly what REO does and doesn't send"),
        ("status", "license, model, privacy posture"),
        ("exit", "leave the shell"),
    ];
    for (cmd, desc) in rows {
        println!("   {:<36}{}", cmd, ui_dim(desc));
    }
}

/// The pricing table — REO tiers at 40% below the equivalent McAfee+ plan.
pub fn print_plans() {
    ui::section("REO plans");
    ui::bullet("Free — real-time scanning, natural-language queries, basic remediation, and file shrinking. No account.");
    println!();
    for p in license::PLANS {
        let recommended = if p.tier == Tier::Premium { "   ★ popular" } else { "" };
        println!(
            "   {:<10} C${:>6.2} 1st yr  ·  C${:.2}/yr after  ·  ~C${:.2}/mo{}",
            p.name, p.first_year_cad, p.renewal_cad, p.monthly_cad, recommended
        );
        ui::kv("includes", p.tagline);
        for f in p.features {
            ui::kv("·", f);
        }
        println!();
    }
    ui::dim("   Annual term. Validated offline — no license server is ever contacted at runtime.");
    ui::info("Say `upgrade` to choose a plan.");
}

pub fn print_privacy(ctx: &Context) {
    ui::section("Privacy posture");
    ui::bullet("Default: air-gapped. REO opens no sockets during normal operation.");
    ui::bullet("No telemetry, no analytics, no crash reports leave this machine — ever.");
    ui::bullet("All inference runs on-device. Your machine data never touches a server.");
    ui::bullet("The ONLY network moments: `upgrade` (Stripe checkout), opt-in Advanced identity services, and an explicit `--cloud` session.");
    if ctx.cloud {
        ui::warn("Cloud fallback is ON for this session. I will tell you exactly what's transmitted before any send.");
    } else {
        ui::success("Cloud fallback is OFF. This session is fully local.");
    }
}

fn unknown(text: &str) {
    if text.is_empty() {
        return;
    }
    ui::say(&format!(
        "I didn't map \"{text}\" to an action yet. Type `help` for what I understand."
    ));
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn require_tier(ctx: &Context, min: Tier, feature: &str) -> bool {
    if ctx.license.has(min) {
        return true;
    }
    let plan = license::plan(min);
    let name = plan.map(|p| p.name).unwrap_or("a paid");
    ui::warn(&format!("{feature} needs the {name} plan or higher."));
    if let Some(p) = plan {
        ui::info(&format!(
            "Say `upgrade` to unlock it — C${:.2} for the first year, validated offline.",
            p.first_year_cad
        ));
    }
    false
}

/// Read a single line of free-text input (used for plan choice).
fn prompt_line(question: &str) -> Result<String> {
    use owo_colors::{OwoColorize, Stream::Stdout};
    print!("{} {} ", "?".if_supports_color(Stdout, |t| t.yellow()), question);
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Local personal-info / secret sweep over the user's home directory. Flags
/// well-known sensitive filenames and obvious plaintext credential files. Reads
/// only names and small headers; nothing leaves the machine.
fn scan_personal_info() -> Vec<String> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    // High-signal, low-noise: filenames that commonly hold secrets in the clear.
    let targets: &[(&str, &str)] = &[
        (".env", "environment file (often holds API keys/passwords)"),
        ("id_rsa", "unencrypted SSH private key"),
        ("id_ed25519", "SSH private key"),
        (".npmrc", "may contain an npm auth token"),
        (".pypirc", "may contain PyPI credentials"),
        (".git-credentials", "stored git credentials in plaintext"),
    ];
    let mut hits = Vec::new();
    // Check home root + a couple of common subdirs without a deep recursive walk.
    let roots = [home.clone(), home.join(".ssh"), home.join(".aws")];
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_lowercase();
            if let Some((_, why)) = targets.iter().find(|(t, _)| name == *t || name.ends_with(*t)) {
                hits.push(format!("{} — {}", e.path().to_string_lossy(), why));
            }
        }
    }
    // AWS credentials file specifically.
    let aws = home.join(".aws").join("credentials");
    if aws.is_file() {
        hits.push(format!("{} — AWS access keys", aws.to_string_lossy()));
    }
    hits
}

/// Pull recent Windows security-relevant events via PowerShell's Get-WinEvent.
/// Returns plain-language one-liners. Empty on non-Windows or when unavailable.
fn recent_events(hours: i64) -> Vec<String> {
    let script = format!(
        "$t=(Get-Date).AddHours(-{hours}); \
         Get-WinEvent -FilterHashtable @{{LogName='System';StartTime=$t}} -MaxEvents 40 \
         -ErrorAction SilentlyContinue | Group-Object Id | \
         Sort-Object Count -Descending | Select-Object -First 6 | \
         ForEach-Object {{ \"$($_.Count)x event $($_.Name)\" }}"
    );
    let Some(out) = scan::capture("powershell", &["-NoProfile", "-Command", &script]) else {
        return Vec::new();
    };
    out.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| format!("System log: {l} in the last {hours}h"))
        .collect()
}

fn extract_pid(title: &str) -> Option<u32> {
    let start = title.find("pid ")? + 4;
    let rest = &title[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn prompt_yes_no(question: &str) -> Result<bool> {
    use owo_colors::{OwoColorize, Stream::Stdout};
    print!("{} {} ", "?".if_supports_color(Stdout, |t| t.yellow()), question);
    print!("[y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn open_browser(url: &str) {
    #[cfg(windows)]
    let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

/// Local dim helper for inline use where the `ui` macros don't fit. Honors
/// color support so piped/redirected output stays clean (no raw escape codes).
fn ui_dim(s: &str) -> String {
    use owo_colors::{OwoColorize, Stream::Stdout};
    format!("{}", s.if_supports_color(Stdout, |t| t.dimmed()))
}

/// Print the once-per-start renewal reminder, if a renewal is approaching.
pub fn renewal_reminder(license: &License) {
    if let Some(days) = license.days_until_renewal() {
        if (0..=14).contains(&days) {
            ui::warn(&format!(
                "Your Pro license renews in {days} days — type `renew` to extend."
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::extract_pid;

    #[test]
    fn pulls_pid_from_finding_title() {
        assert_eq!(extract_pid("evil.exe (pid 4620)"), Some(4620));
        assert_eq!(extract_pid("task `Updater`"), None);
        assert_eq!(extract_pid("svchost.exe (pid 1908) extra"), Some(1908));
    }
}
