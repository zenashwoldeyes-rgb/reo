//! The persistent secure REPL. When REO runs with no subcommand this is the
//! product: a local shell where you talk to your machine in natural language.

use crate::config::Context;
use crate::{commands, intent, model, ui};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::Result;

pub fn run(ctx: &mut Context) -> Result<()> {
    ui::banner();

    // First-run / status line.
    let m = model::detect(ctx);
    ui::kv("tier", ctx.license.tier().label());
    ui::kv("privacy", if ctx.cloud { "cloud fallback ENABLED" } else { "air-gapped" });
    ui::kv("model", m.backend);
    if !m.present {
        ui::dim("   No local model installed yet — using the heuristic engine. `status` for the path.");
    }
    commands::renewal_reminder(&ctx.license);

    println!();
    ui::say("I'm listening. Try \"scan my computer\" or type `help`. `exit` to leave.");

    let mut rl = DefaultEditor::new()?;
    loop {
        match rl.readline("reo › ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);

                let intent = intent::route(line);
                match commands::handle(ctx, intent) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) => ui::error(&format!("{e}")),
                }
                println!();
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C: clear the line, stay in the shell.
                continue;
            }
            Err(ReadlineError::Eof) => break, // Ctrl-D
            Err(e) => {
                ui::error(&format!("input error: {e}"));
                break;
            }
        }
    }

    ui::say("Staying local. Goodbye.");
    Ok(())
}
