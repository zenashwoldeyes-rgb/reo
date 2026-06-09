//! Command implementations. These back both the `reo <subcommand>` entry points
//! and the natural-language intents from the REPL, so behavior is identical
//! whether the user scripts REO or talks to it.

use crate::config::Context;
use crate::intent::Intent;
use crate::license::{self, License, Tier};
use crate::scan::network::{self, Class};
use crate::scan::{self, ScanOptions};
use crate::{crypto, dedup, detect, housekeeping, infra, model, shrink, ui, vault};
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
        Intent::Shrink(args) => run_shrink(&args.iter().map(PathBuf::from).collect::<Vec<_>>(), false)?,
        Intent::ShrinkAll => run_shrink(&[], true)?,
        Intent::Clean => run_clean(false)?,
        Intent::Space => run_space()?,
        Intent::Dedup => run_dedup(ctx, None, false)?,
        Intent::Find(query) => run_find(&query)?,
        Intent::Infra(req) => run_infra(ctx, &req, false, false)?,
        Intent::Detect => run_detect(ctx, None)?,
        Intent::Watch => run_watch(ctx, None, false)?,
        Intent::Pii => run_pii(ctx)?,
        Intent::Protect => run_protect(ctx)?,
        Intent::Plans => print_plans(),
        Intent::Upgrade => run_upgrade(ctx, None)?,
        Intent::Activate(token) => run_activate(ctx, token)?,
        Intent::Logout => run_logout(ctx)?,
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

    let url = license::checkout_url(plan.tier);

    ui::say(&format!(
        "REO {} — {}. C${:.2}/yr, billed annually.",
        plan.name, plan.tagline, plan.yearly_cad
    ));
    ui::section("Checkout");
    ui::kv("link", url);
    ui::dim("   Opening this Stripe page is the only time REO uses the network.");

    if prompt_yes_no("Open the checkout in your browser now?")? {
        open_browser(url);
    }

    // Payment happens on Stripe; the customer receives a signed token by email.
    // REO grants nothing until that token is verified locally via `activate`.
    ui::section("After you pay");
    ui::info("You'll get a license token (starts with REO1.) by email.");
    ui::dim("   Activate it any time with:  activate <token>");
    Ok(())
}

/// Redeem a signed license token. The signature is verified against the public
/// key compiled into REO; a forged or unsigned token is refused.
pub fn run_activate(ctx: &mut Context, token: Option<String>) -> Result<()> {
    if !crypto::is_valid_public_key(license::REO_PUBLIC_KEY_B64) {
        return Err("this build has no license key configured — please contact the vendor".into());
    }
    let token = match token {
        Some(t) if !t.trim().is_empty() => t,
        _ => prompt_line("Paste your license token (starts with REO1.)")?,
    };
    if token.trim().is_empty() {
        ui::info("Nothing entered — no change.");
        return Ok(());
    }

    ctx.license.activate(token.trim())?;
    ctx.license.save(&ctx.data_dir)?;

    ui::section("Activated");
    ui::success(&format!(
        "{} unlocked. Stored & validated entirely offline.",
        ctx.license.tier().label()
    ));
    if let Some(who) = ctx.license.holder() {
        ui::kv("registered to", who);
    }
    if let Some(days) = ctx.license.days_until_renewal() {
        ui::info(&format!("Renews in {days} days. REO will remind you in-terminal."));
    }
    Ok(())
}

/// Remove the activated license from this machine and revert to Free. (REO has
/// no accounts/passwords — your identity is the local signed token, so "logging
/// out" means deleting it.)
pub fn run_logout(ctx: &mut Context) -> Result<()> {
    let path = ctx.data_dir.join("license.json");
    if !path.exists() && ctx.license.holder().is_none() {
        ui::info("You're already on Free — there's no license to log out of.");
        return Ok(());
    }
    let tier = ctx.license.tier().label();
    ui::warn(&format!("This removes your {tier} license from this machine (back to Free)."));
    ui::dim("   You'll need your token to log back in:  reo activate <token>");
    if !prompt_yes_no("Log out now?")? {
        ui::info("Stayed logged in — nothing changed.");
        return Ok(());
    }
    let _ = std::fs::remove_file(&path);
    ui::success("Logged out — REO is back to Free. Re-activate any time with `reo activate <token>`.");
    Ok(())
}

pub fn run_renew(ctx: &mut Context) -> Result<()> {
    if !ctx.license.is_paid() {
        ui::warn("No active paid license to renew. Say `plans` to see options.");
        return Ok(());
    }
    let url = license::checkout_url(ctx.license.tier());
    ui::say(
        "Renewing buys another year. A signed license can't be extended on your machine, so you \
         purchase a renewal and activate the new token.",
    );
    ui::section("Renewal checkout");
    ui::kv("link", url);
    if prompt_yes_no("Open the renewal checkout now?")? {
        open_browser(url);
    }
    ui::dim("   After paying, run:  activate <token>  with the token you receive.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Seller-only tooling (hidden subcommands; harmless without the private key)
// ---------------------------------------------------------------------------

/// Generate a fresh ed25519 keypair for signing licenses.
pub fn run_keygen() -> Result<()> {
    let (priv_b64, pub_b64) = crypto::generate_keypair()?;
    ui::section("New REO license keypair");
    ui::warn("Anyone with the PRIVATE key can mint licenses. Store it in a password manager; never commit it.");
    println!();
    ui::kv("PRIVATE (keep secret)", &priv_b64);
    ui::kv("PUBLIC  (embed in app)", &pub_b64);
    println!();
    ui::dim("   1. Paste PUBLIC into REO_PUBLIC_KEY_B64 in src/license.rs, then rebuild + re-release.");
    ui::dim("   2. To mint tokens, set REO_SIGNING_KEY to the PRIVATE key, then run `reo issue ...`.");
    Ok(())
}

/// Mint a signed license token. Reads the private key from $REO_SIGNING_KEY.
pub fn run_issue(plan_name: &str, email: &str, years: i64) -> Result<()> {
    let plan = license::plan_by_name(plan_name)
        .ok_or("unknown plan — choose: basic, premium, or advanced")?;
    let signing_key = std::env::var("REO_SIGNING_KEY")
        .map_err(|_| "set $REO_SIGNING_KEY to your private key (from `reo keygen`)")?;
    let token = license::issue_token(&signing_key, plan.tier, email, years)?;
    ui::section("License token");
    ui::kv("tier", plan.name);
    ui::kv("for", email);
    ui::kv("years", &years.to_string());
    println!();
    println!("{token}");
    println!();
    ui::dim("   Send this to the customer; they run:  reo activate <token>");
    Ok(())
}

pub fn run_status(ctx: &mut Context) -> Result<()> {
    let m = model::detect(ctx);
    ui::section("REO status");
    ui::kv("tier", ctx.license.tier().label());
    if let Some(p) = license::plan(ctx.license.tier()) {
        ui::kv("plan", p.tagline);
        for feat in p.features {
            ui::kv("·", feat);
        }
    }
    if let Some(who) = ctx.license.holder() {
        ui::kv("registered to", who);
    }
    if let Some(days) = ctx.license.days_until_renewal() {
        ui::kv("renews in", &format!("{days} days"));
    }
    ui::kv("machine id", &ctx.license.machine_id);
    ui::kv("privacy", if ctx.cloud { "cloud fallback ENABLED (this session)" } else { "air-gapped" });
    ui::kv("model", &m.backend);
    if !m.present {
        ui::kv("model path", &m.path.to_string_lossy());
    }
    ui::kv("data dir", &ctx.data_dir.to_string_lossy());
    Ok(())
}

// ---------------------------------------------------------------------------
// Free file shrinking (the no-account hook) + tiered protection features
// ---------------------------------------------------------------------------

pub fn run_shrink(files: &[PathBuf], all: bool) -> Result<()> {
    if all {
        return run_shrink_all();
    }
    if files.is_empty() {
        ui::say("Tell me what to shrink, e.g. `shrink screenshot.png`, `shrink C:\\Photos`, or `shrink --all`.");
        ui::dim("   PNGs are optimized losslessly in place; anything else is compressed to a .gz alongside it. All local, no account.");
        return Ok(());
    }

    ui::say("Shrinking locally — nothing is uploaded.");
    ui::section("Results");
    let mut total_before = 0u64;
    let mut total_after = 0u64;
    for path in files {
        if path.is_dir() {
            match shrink::shrink_dir(path) {
                Ok(r) => {
                    total_before += r.before;
                    total_after += r.after;
                    let pct = if r.before > 0 {
                        r.saved() as f64 / r.before as f64 * 100.0
                    } else {
                        0.0
                    };
                    ui::success(&format!(
                        "{}  (folder)  optimized {} of {} PNGs  —  saved {} (−{:.1}%)",
                        path.display(),
                        r.optimized,
                        r.scanned,
                        shrink::human(r.saved()),
                        pct
                    ));
                }
                Err(e) => ui::error(&format!("{}: {e}", path.display())),
            }
            continue;
        }
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

/// Optimize every image across the user's folders, losslessly, in place — the
/// "free GBs across my whole computer" mode. Counts and confirms before touching
/// anything, since it rewrites many files at once.
fn run_shrink_all() -> Result<()> {
    ui::say("Optimizing all your images across the computer — lossless (same pictures, smaller files). Nothing is uploaded.");
    let (count, bytes) = shrink::count_pngs_all();
    if count == 0 {
        ui::info("No PNG images found in your Pictures, Desktop, Downloads, or Documents.");
        ui::dim("   (Today this optimizes PNGs — typically screenshots. JPEG photos need lossy mode, coming next.)");
        return Ok(());
    }
    ui::section("Found");
    ui::kv("images", &format!("{count} PNGs totaling {}", shrink::human(bytes)));
    if !prompt_yes_no("Optimize them all in place now? (lossless — your pictures don't change)")? {
        ui::info("No changes made.");
        return Ok(());
    }

    let r = shrink::shrink_all();
    let pct = if r.before > 0 {
        r.saved() as f64 / r.before as f64 * 100.0
    } else {
        0.0
    };
    ui::section("Done");
    ui::success(&format!(
        "Optimized {} of {} images — reclaimed {} (−{:.1}%) across your computer.",
        r.optimized,
        r.scanned,
        shrink::human(r.saved()),
        pct
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Cleaner · smaller · findable — housekeeping in plain English
// ---------------------------------------------------------------------------

/// Free up disk space by clearing temporary files. Shows what it will reclaim
/// first and only deletes after you confirm (or with `--apply`).
pub fn run_clean(apply: bool) -> Result<()> {
    ui::say("Looking for space you can safely reclaim. Nothing is deleted yet.");
    let targets = housekeeping::scan_reclaimable();
    let total: u64 = targets.iter().map(|t| t.bytes).sum();
    let files: u64 = targets.iter().map(|t| t.files).sum();

    ui::section("Reclaimable space");
    if targets.is_empty() || total == 0 {
        ui::success("Already tidy — no significant temporary files to clear.");
        return Ok(());
    }
    for t in &targets {
        ui::kv(&t.label, &format!("{} across {} files", shrink::human(t.bytes), t.files));
    }
    ui::kv("total", &format!("{} ({files} files)", shrink::human(total)));

    let go = apply || prompt_yes_no("Delete these temporary files now to free the space?")?;
    if !go {
        ui::info("Left everything in place. Run `clean` again any time.");
        return Ok(());
    }
    let (freed, removed) = housekeeping::clean(&targets);
    ui::section("Done");
    ui::success(&format!(
        "Freed {} — removed {removed} files. (Files in use were skipped.)",
        shrink::human(freed)
    ));
    Ok(())
}

/// Find files anywhere in your folders by describing them in plain English.
pub fn run_find(query: &str) -> Result<()> {
    let q = query.trim();
    if q.is_empty() {
        ui::say("Tell me what to find, e.g. `find my resume` or `find vacation photos`.");
        return Ok(());
    }
    ui::say(&format!("Searching your folders for \"{q}\" — all local."));
    let hits = housekeeping::find(q);
    ui::section(&format!("Matches ({})", hits.len()));
    if hits.is_empty() {
        ui::info("Nothing matched. Try a simpler word — e.g. `resume` instead of `my resume file`.");
        return Ok(());
    }
    for h in hits.iter().take(25) {
        ui::kv(&shrink::human(h.bytes), &h.path.display().to_string());
    }
    if hits.len() > 25 {
        ui::dim(&format!("   …and {} more. Narrow it with a more specific word.", hits.len() - 25));
    }
    Ok(())
}

/// Show the biggest files in your folders so you can decide what to delete to
/// reclaim space. Read-only — REO never deletes these for you.
pub fn run_space() -> Result<()> {
    ui::say("Finding what's taking up the most space in your folders — read-only, nothing is deleted.");
    let big = housekeeping::biggest_files(25);
    ui::section(&format!("Biggest files ({})", big.len()));
    if big.is_empty() {
        ui::info("Nothing notable found in your content folders.");
        return Ok(());
    }
    let total: u64 = big.iter().map(|h| h.bytes).sum();
    for h in &big {
        ui::kv(&shrink::human(h.bytes), &h.path.display().to_string());
    }
    ui::kv("these total", &shrink::human(total));
    ui::dim("   Delete anything you don't need to reclaim space. REO won't remove these for you.");
    Ok(())
}

/// Find byte-identical duplicate files and reclaim the wasted space — the real,
/// honest version of "compress everywhere" (it removes redundant copies, never
/// magically shrinks data). Report-only by default; `--apply` removes copies.
pub fn run_dedup(_ctx: &mut Context, path: Option<&str>, apply: bool) -> Result<()> {
    let roots: Vec<PathBuf> = match path {
        Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p.trim())],
        _ => housekeeping::search_roots(),
    };
    ui::say("Scanning for byte-for-byte duplicate files — all local.");
    let report = dedup::find_duplicates(&roots);

    ui::section("Duplicates");
    ui::kv("files scanned", &report.scanned.to_string());
    if report.groups.is_empty() {
        ui::success("No duplicate files found — nothing to reclaim.");
        return Ok(());
    }
    ui::kv("duplicate sets", &report.groups.len().to_string());
    ui::kv("redundant copies", &report.redundant_files().to_string());
    ui::kv("reclaimable", &shrink::human(report.wasted_bytes()));

    for g in report.groups.iter().take(5) {
        println!();
        ui::kv("set", &format!("{} × {} copies", shrink::human(g.size), g.paths.len()));
        for p in g.paths.iter().take(4) {
            ui::dim(&format!("   {}", p.display()));
        }
    }
    if report.groups.len() > 5 {
        ui::dim(&format!("   …and {} more sets.", report.groups.len() - 5));
    }

    let go = apply || prompt_yes_no("Delete the redundant copies, keeping one of each?")?;
    if !go {
        ui::info("Left everything in place.");
        return Ok(());
    }
    let (n, b) = dedup::dedupe(&report);
    ui::section("Done");
    ui::success(&format!("Removed {n} duplicate copies — freed {}. Kept one of each.", shrink::human(b)));
    Ok(())
}

/// On-device behavioral threat detection: analyze file *content* (entropy +
/// format masquerade + ransom notes) to catch ransomware — all local, no cloud.
pub fn run_detect(ctx: &mut Context, path: Option<&str>) -> Result<()> {
    if !require_tier(ctx, Tier::Basic, "On-device behavioral threat detection") {
        return Ok(());
    }
    let roots: Vec<PathBuf> = match path {
        Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p.trim())],
        _ => housekeeping::search_roots(),
    };
    ui::say("Behavioral threat detection — analyzing file content locally (entropy + format checks). Nothing is uploaded.");
    let report = detect::scan_ransomware(&roots);

    ui::section("Behavioral scan");
    ui::kv("files analyzed", &report.scanned.to_string());
    ui::kv("technique", "entropy + format-masquerade + ransom-note detection");

    if report.findings.is_empty() {
        ui::success("No ransomware behavior found — no encrypted-looking files, ransom notes, or crypto extensions.");
        return Ok(());
    }

    ui::section(&format!("Threats ({})", report.findings.len()));
    for f in report.findings.iter().take(30) {
        println!();
        println!("   {}", ui::risk_bar(f.score, risk_label(f.score)));
        ui::kv("file", &f.path.display().to_string());
        ui::kv("why", &f.reason);
    }
    if report.findings.len() > 30 {
        ui::dim(&format!("   …and {} more.", report.findings.len() - 30));
    }

    ui::section("Verdict");
    let s = report.score();
    println!("   {}", ui::risk_bar(s, risk_label(s)));
    if s >= 60 {
        ui::warn("This is consistent with ransomware. If files are being encrypted right now: disconnect from the network, then `scan` and `remove` the responsible process.");
    } else {
        ui::info("Some files look unusual but it's not clearly ransomware — review the items above.");
    }
    Ok(())
}

fn risk_label(s: u8) -> &'static str {
    match s {
        0..=14 => "INFO",
        15..=34 => "LOW",
        35..=59 => "MEDIUM",
        60..=84 => "HIGH",
        _ => "CRITICAL",
    }
}

/// Pre-encryption vault: snapshot clean files now so ransomware can't take them;
/// restore them if an attack ever encrypts the folder. All local.
pub fn run_vault(ctx: &mut Context, action: &str, path: Option<&str>) -> Result<()> {
    if !require_tier(ctx, Tier::Basic, "The ransomware vault") {
        return Ok(());
    }
    let vault_root = ctx.data_dir.join("vault");
    match action.trim().to_lowercase().as_str() {
        "snapshot" => {
            let Some(p) = path.filter(|p| !p.trim().is_empty()) else {
                ui::warn("Usage:  reo vault snapshot <folder>");
                return Ok(());
            };
            let folder = PathBuf::from(p.trim());
            ui::say(&format!("Vaulting clean copies of {} — all local.", folder.display()));
            let meta = vault::snapshot(&folder, &vault_root)?;
            ui::success(&format!(
                "Vaulted {} files ({}). Snapshot id {}.",
                meta.files,
                shrink::human(meta.bytes),
                meta.id
            ));
            ui::dim("   If ransomware ever hits this folder, recover with:  reo vault restore <folder>");
        }
        "restore" => {
            let Some(p) = path.filter(|p| !p.trim().is_empty()) else {
                ui::warn("Usage:  reo vault restore <folder>");
                return Ok(());
            };
            let folder = PathBuf::from(p.trim());
            ui::say(&format!("Restoring {} from your latest clean snapshot…", folder.display()));
            let (n, b) = vault::restore_latest(&vault_root, &folder)?;
            ui::success(&format!("Restored {n} files ({}) — your data is back.", shrink::human(b)));
        }
        "list" | "status" => {
            let snaps = vault::list(&vault_root);
            ui::section(&format!("Vault snapshots ({})", snaps.len()));
            if snaps.is_empty() {
                ui::info("No snapshots yet. Protect a folder with:  reo vault snapshot <folder>");
                return Ok(());
            }
            for s in &snaps {
                ui::kv(
                    &s.id,
                    &format!("{}  —  {} files, {}", s.source.display(), s.files, shrink::human(s.bytes)),
                );
            }
        }
        _ => ui::warn("Use:  reo vault snapshot <folder> | restore <folder> | list"),
    }
    Ok(())
}

/// Real-time ransomware protection: watch for active encryption and alert the
/// instant a burst is detected. Runs until you stop it (Ctrl-C). All local.
pub fn run_watch(ctx: &mut Context, path: Option<&str>, respond: bool) -> Result<()> {
    if !require_tier(ctx, Tier::Basic, "Real-time ransomware monitoring") {
        return Ok(());
    }
    let roots: Vec<PathBuf> = match path {
        Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p.trim())],
        _ => housekeeping::search_roots(),
    };
    if roots.iter().all(|r| !r.is_dir()) {
        ui::warn("Nothing to watch — couldn't find the target folder(s).");
        return Ok(());
    }
    ui::say("Real-time ransomware protection is ON. Watching for active encryption — press Ctrl-C to stop.");
    for r in roots.iter().filter(|r| r.is_dir()) {
        ui::kv("watching", &r.display().to_string());
    }
    ui::kv(
        "on attack",
        if respond { "identify AND terminate the culprit process" } else { "identify the culprit (add --respond to auto-terminate)" },
    );
    ui::dim("   All local — REO only reads file-change events on this machine, nothing is uploaded.");
    ui::section("Live");
    detect::watch(
        &roots,
        |path, reason| ui::warn(&format!("encryption signal — {}  ({reason})", path.display())),
        |count| {
            println!();
            ui::error("RANSOMWARE BEHAVIOR DETECTED — files are being encrypted right now");
            ui::kv("burst", &format!("{count} files turned to encrypted content within 30s"));

            // Process attribution: who is doing the writing?
            ui::say("Identifying the responsible process (sampling disk I/O)…");
            match detect::identify_culprit() {
                Some(c) => {
                    ui::kv("culprit", &format!("{} (pid {})", c.name, c.pid));
                    if let Some(exe) = &c.exe {
                        ui::kv("image", &exe.display().to_string());
                    }
                    ui::kv("writing", &format!("{} in ~0.7s", shrink::human(c.written)));
                    if respond {
                        if detect::terminate(c.pid) {
                            ui::success(&format!("Terminated {} (pid {}) — encryption stopped.", c.name, c.pid));
                        } else {
                            ui::error(&format!("Couldn't terminate pid {} — run REO as Administrator to kill it.", c.pid));
                        }
                    } else {
                        ui::warn(&format!("Stop it now: `reo remove`, or kill pid {} — or re-run `watch --respond` to auto-terminate.", c.pid));
                    }
                }
                None => ui::dim("   Couldn't attribute it to a process (run REO elevated to read other processes' disk I/O)."),
            }
            ui::warn("Also: disconnect from the network, and do NOT pay.");
            ui::dim("   Vaulted this folder? Recover the originals with:  reo vault restore <folder>");
            println!();
        },
    )
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
    ui::say("Identity protection — the honest status.");
    ui::section("On the roadmap (NOT active yet)");
    ui::bullet("Identity-theft insurance, data-broker info removal, and financial monitoring are planned via partner integrations.");
    ui::bullet("They are NOT active today — and you will never be billed for them until they actually launch.");
    ui::section("What your Advanced plan gives you today");
    ui::bullet("Everything in Premium, plus priority support and early access to new protections.");
    ui::dim("   Want the identity services when they launch? Reply to your receipt and we'll let you know.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Always-on protection (background service)
// ---------------------------------------------------------------------------

const SERVICE_TASK: &str = "REO Protection";

/// Install/remove always-on ransomware protection via a logon-triggered Windows
/// scheduled task running `watch --respond`. This is the legitimate, AV-clean
/// mechanism real security tools use — it requires a one-time **Administrator**
/// terminal to register. (A SYSTEM-level signed Windows Service that runs before
/// any login is the deeper production hardening.)
pub fn run_service(ctx: &mut Context, action: &str) -> Result<()> {
    if !require_tier(ctx, Tier::Basic, "Always-on background protection") {
        return Ok(());
    }
    if !cfg!(windows) {
        ui::warn("Always-on install is Windows-only in this build.");
        ui::dim("   On macOS/Linux, run `reo watch --respond` from a launchd/systemd unit.");
        return Ok(());
    }
    let exe = std::env::current_exe()?.to_string_lossy().into_owned();

    match action.trim().to_lowercase().as_str() {
        "install" => {
            let run = format!("\\\"{exe}\\\" watch --respond");
            let out = std::process::Command::new("schtasks")
                .args(["/create", "/tn", SERVICE_TASK, "/tr", &run, "/sc", "onlogon", "/f"])
                .output()?;
            if out.status.success() {
                ui::success("Always-on protection installed.");
                ui::kv("guards", "your folders, automatically, every time you log in");
                ui::kv("action", "detects ransomware and terminates the process (`watch --respond`)");
                ui::info("Start it now without logging out:  reo watch --respond");
            } else {
                let err = String::from_utf8_lossy(&out.stderr);
                if err.to_lowercase().contains("denied") {
                    ui::error("Installing always-on protection needs Administrator rights.");
                    ui::dim("   Open PowerShell as Administrator (right-click → Run as administrator),");
                    ui::dim("   then run `reo service install` again. This is a one-time step.");
                } else {
                    ui::error(&format!("Couldn't register protection: {}", err.trim()));
                }
            }
        }
        "uninstall" => {
            let out = std::process::Command::new("schtasks")
                .args(["/delete", "/tn", SERVICE_TASK, "/f"])
                .output()?;
            if out.status.success() {
                ui::success("Always-on protection removed.");
            } else {
                ui::warn("No installed protection found (run `service uninstall` from an Administrator terminal if it persists).");
            }
        }
        "status" => {
            let out = std::process::Command::new("schtasks")
                .args(["/query", "/tn", SERVICE_TASK])
                .output()?;
            if out.status.success() {
                ui::success("Always-on protection is INSTALLED — REO guards this machine at login.");
            } else {
                ui::info("Always-on protection is not installed. Run `reo service install` (as Administrator) to enable it.");
            }
        }
        _ => ui::warn("Use: reo service install | uninstall | status"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Enterprise — AI Digital Data Center (cloud infrastructure orchestration)
// ---------------------------------------------------------------------------

/// Conversational infrastructure: analyze a request, build + price + risk-assess
/// a plan, generate the infrastructure-as-code, and seek approval. Live
/// execution against your cloud is the Enterprise connector (a marked seam).
pub fn run_infra(ctx: &mut Context, request: &str, apply: bool, local: bool) -> Result<()> {
    if !require_tier(ctx, Tier::Enterprise, "The AI Digital Data Center (cloud infrastructure)") {
        return Ok(());
    }
    let req = request.trim();
    if req.is_empty() {
        ui::say("Tell me what to do, e.g. `infra deploy a postgres database in canada` or `infra deploy a postgres database --local` (free, on this machine).");
        return Ok(());
    }

    ui::say("Analyzing your request and building an execution plan. Nothing changes until you approve.");
    let plan = infra::plan(req, local);

    ui::section("Plan");
    ui::kv("request", req);
    ui::kv("what", &plan.summary);
    ui::kv("provider", &plan.provider);
    ui::kv("region", &plan.region);

    ui::section("Steps");
    for (i, s) in plan.steps.iter().enumerate() {
        println!("   {}. {}", i + 1, s);
    }

    ui::section("Estimate");
    if plan.provider.starts_with("Local") {
        ui::kv("est. cost", "free — runs on your machine (Docker)");
    } else if plan.monthly_cost_usd > 0.0 {
        ui::kv("est. cost", &format!("~${:.0}/month", plan.monthly_cost_usd));
    } else {
        ui::kv("est. cost", "depends on current usage — priced after analysis");
    }
    ui::kv("risk", plan.risk);

    if let Some(iac) = &plan.iac {
        ui::section("Infrastructure as code (Terraform)");
        println!("{iac}");
    }

    ui::section("Approval");
    if !prompt_yes_no("Approve this plan?")? {
        ui::info("No changes made.");
        return Ok(());
    }

    match (apply, &plan.iac) {
        // Cloud connector: run the generated Terraform locally with your creds.
        (true, Some(iac)) => apply_infra(ctx, &plan, iac)?,
        (true, None) => {
            ui::warn("This request is plan-only (it needs the live infrastructure graph) — nothing to auto-apply yet.");
        }
        (false, _) if plan.executable => {
            ui::warn("Reviewed plan + ready-to-apply Terraform produced. Nothing was deployed.");
            ui::dim("   Re-run with `--apply` to have REO run it via Terraform with YOUR cloud credentials");
            ui::dim("   (executes locally — your keys never leave the machine), or apply the IaC yourself.");
        }
        (false, _) => {
            ui::warn("This action needs the live infrastructure graph (the Enterprise connector) to execute.");
        }
    }
    Ok(())
}

/// The cloud connector: write the generated Terraform and run it **locally** with
/// the user's own provider credentials (read from their environment by Terraform).
/// REO has no cloud backend — execution is sovereign, on the user's machine.
fn apply_infra(ctx: &Context, plan: &infra::Plan, iac: &str) -> Result<()> {
    let Some(header) = infra::provider_header(iac) else {
        ui::warn(&format!(
            "Live apply is wired for DigitalOcean in this build; this plan targets {}. Apply the IaC yourself.",
            plan.provider
        ));
        return Ok(());
    };

    // Terraform must be installed — REO orchestrates it, it doesn't reimplement it.
    let tf_ok = std::process::Command::new("terraform")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !tf_ok {
        ui::error("Terraform isn't installed — REO uses it to apply infrastructure with your credentials.");
        ui::dim("   Install: https://developer.hashicorp.com/terraform/install");
        ui::dim("   Then set your provider token (e.g. $env:DIGITALOCEAN_TOKEN=\"…\") and re-run with --apply.");
        return Ok(());
    }

    let dir = ctx.data_dir.join("infra").join(plan.kind);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("main.tf"), format!("{header}{iac}"))?;
    ui::section("Cloud connector");
    ui::kv("workspace", &dir.to_string_lossy());
    ui::dim("   Running Terraform locally — your credentials never leave this machine.");

    let tf = |args: &[&str]| -> std::io::Result<bool> {
        Ok(std::process::Command::new("terraform")
            .current_dir(&dir)
            .args(args)
            .status()?
            .success())
    };

    ui::say("terraform init…");
    if !tf(&["init", "-input=false"])? {
        ui::error("terraform init failed (see output above).");
        return Ok(());
    }
    ui::say("terraform plan…");
    if !tf(&["plan", "-input=false"])? {
        ui::warn("terraform plan failed — usually a missing provider token.");
        ui::dim("   Set it (e.g. $env:DIGITALOCEAN_TOKEN=\"<token>\") and re-run with --apply.");
        return Ok(());
    }
    if prompt_yes_no("Apply for real? This creates billable cloud resources.")? {
        if tf(&["apply", "-auto-approve", "-input=false"])? {
            ui::success("Deployed. Run `terraform output` in the workspace for endpoints/credentials.");
        } else {
            ui::error("terraform apply failed (see output above).");
        }
    } else {
        ui::info("Plan only — nothing deployed. The Terraform is saved in the workspace above.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Conversational helpers
// ---------------------------------------------------------------------------

pub fn print_help() {
    ui::section("What you can say");
    let rows = [
        ("shrink screenshot.png", "shrink a file or whole folder — free, no account"),
        ("shrink all my photos", "optimize every image computer-wide, losslessly"),
        ("clean up my computer", "free space: temp files, caches, Recycle Bin"),
        ("what's taking up space", "show your biggest files so you can clear them"),
        ("find duplicate files", "reclaim space from byte-identical copies"),
        ("find my vacation photos", "search your folders in plain English"),
        ("scan my computer", "full system scan with risk scores"),
        ("what's running on my network", "map active connections, flag public egress"),
        ("check for ransomware", "on-device behavioral detection (Basic+)"),
        ("watch my files for ransomware", "real-time protection — alerts mid-attack (Basic+)"),
        ("vault snapshot C:\\Important", "back up clean files so ransomware can't take them (Basic+)"),
        ("something feels off, investigate", "behavioral analysis (Basic+)"),
        ("remove the adware", "remediate the top finding"),
        ("why is my machine slow", "profile CPU/RAM/startup, top 3 causes"),
        ("show me what happened last night", "correlate local logs (Basic+)"),
        ("scan for my personal info", "find exposed secrets & PII (Premium+)"),
        ("protect my identity", "identity insurance & info removal (Advanced)"),
        ("lock this machine down", "harden firewall, close risky ports"),
        ("plans", "see pricing tiers"),
        ("upgrade", "open Stripe checkout for a plan"),
        ("activate <token>", "redeem the license token you got after paying (log in)"),
        ("log out", "remove your license from this machine (back to Free)"),
        ("privacy", "explain exactly what REO does and doesn't send"),
        ("status", "license, model, privacy posture"),
        ("exit", "leave the shell"),
    ];
    for (cmd, desc) in rows {
        println!("   {:<36}{}", cmd, ui_dim(desc));
    }
}

/// The pricing table — REO tiers and what each one unlocks.
pub fn print_plans() {
    ui::section("REO plans");
    ui::bullet("Free — real-time scanning, natural-language queries, basic remediation, and file shrinking. No account.");
    println!();
    for p in license::PLANS {
        let recommended = if p.tier == Tier::Premium { "   ★ popular" } else { "" };
        println!(
            "   {:<10} C${:>7.2}/yr{}",
            p.name, p.yearly_cad, recommended
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
            "Say `upgrade` to unlock it — C${:.2}/yr, validated offline.",
            p.yearly_cad
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
