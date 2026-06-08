//! Terminal presentation. All colored output flows through here so the look
//! stays consistent and so we can fall back to plain text when stdout is not a
//! TTY (piped output, CI, etc.).

use owo_colors::{OwoColorize, Stream::Stdout, Style};

const ACCENT: (u8, u8, u8) = (94, 231, 223); // REO teal

/// The boot banner shown when the interactive shell starts.
pub fn banner() {
    let art = r#"
   ██████╗ ███████╗ ██████╗
   ██╔══██╗██╔════╝██╔═══██╗
   ██████╔╝█████╗  ██║   ██║
   ██╔══██╗██╔══╝  ██║   ██║
   ██║  ██║███████╗╚██████╔╝
   ╚═╝  ╚═╝╚══════╝ ╚═════╝
"#;
    println!(
        "{}",
        art.if_supports_color(Stdout, |t| t.truecolor(ACCENT.0, ACCENT.1, ACCENT.2))
    );
    println!(
        "   {}",
        "local AI security engineer · never phones home"
            .if_supports_color(Stdout, |t| t.dimmed())
    );
}

pub fn section(title: &str) {
    println!();
    println!(
        "{} {}",
        "▌".if_supports_color(Stdout, |t| t.truecolor(ACCENT.0, ACCENT.1, ACCENT.2)),
        title.if_supports_color(Stdout, |t| t.bold())
    );
}

/// A `key: value` line, right-aligned key for a tidy column.
pub fn kv(key: &str, value: &str) {
    println!(
        "   {:>14}  {}",
        key.if_supports_color(Stdout, |t| t.dimmed()),
        value
    );
}

pub fn bullet(text: &str) {
    println!(
        "   {} {}",
        "•".if_supports_color(Stdout, |t| t.dimmed()),
        text
    );
}

pub fn success(text: &str) {
    println!(
        "{} {}",
        "✓".if_supports_color(Stdout, |t| t.green()),
        text
    );
}

pub fn warn(text: &str) {
    println!(
        "{} {}",
        "!".if_supports_color(Stdout, |t| t.yellow()),
        text
    );
}

pub fn error(text: &str) {
    eprintln!(
        "{} {}",
        "✗".if_supports_color(Stdout, |t| t.red()),
        text
    );
}

pub fn info(text: &str) {
    println!(
        "{} {}",
        "›".if_supports_color(Stdout, |t| t.truecolor(ACCENT.0, ACCENT.1, ACCENT.2)),
        text
    );
}

pub fn dim(text: &str) {
    println!("{}", text.if_supports_color(Stdout, |t| t.dimmed()));
}

/// Echo the REO "voice" — what the agent says back in conversation.
pub fn say(text: &str) {
    let voice = Style::new().truecolor(ACCENT.0, ACCENT.1, ACCENT.2).bold();
    println!(
        "{} {}",
        "reo".if_supports_color(Stdout, |t| t.style(voice)),
        text
    );
}

/// Render a 0–100 risk score as a colored bar, e.g. `[██████░░░░] 61  HIGH`.
pub fn risk_bar(score: u8, label: &str) -> String {
    let filled = (score as usize * 10 / 100).min(10);
    let bar: String = "█".repeat(filled) + &"░".repeat(10 - filled);
    let colored = match score {
        0..=24 => format!("{}", bar.if_supports_color(Stdout, |t| t.green())),
        25..=49 => format!("{}", bar.if_supports_color(Stdout, |t| t.yellow())),
        50..=74 => format!(
            "{}",
            bar.if_supports_color(Stdout, |t| t.truecolor(255, 165, 0))
        ),
        _ => format!("{}", bar.if_supports_color(Stdout, |t| t.red())),
    };
    format!("[{colored}] {score:>3}  {label}")
}
