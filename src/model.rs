//! Local inference layer.
//!
//! In production this wraps a bundled llama.cpp build running a quantized,
//! security-fine-tuned 7B/13B model fully on-device. The trait below is the
//! seam that backend plugs into. Until a GGUF is present, REO uses a
//! deterministic `HeuristicModel` so every command still produces plain-language
//! narration — the agent is useful with zero downloads, and gets sharper when
//! the real model is installed.

use crate::config::Context;
use std::path::PathBuf;

pub trait LocalModel {
    /// Turn a topic plus a set of observed facts into a plain-language
    /// explanation. Real backend: a prompt to the on-device LLM. Fallback:
    /// templated synthesis from the facts.
    fn narrate(&self, topic: &str, facts: &[String]) -> String;
}

/// Zero-dependency fallback. Honest about being a template engine, not an LLM.
pub struct HeuristicModel;

impl LocalModel for HeuristicModel {
    fn narrate(&self, topic: &str, facts: &[String]) -> String {
        if facts.is_empty() {
            return format!("On {topic}: nothing notable stood out.");
        }
        let mut out = format!("On {topic}, here's what I see:\n");
        for f in facts {
            out.push_str(&format!("  • {f}\n"));
        }
        out.push_str("Install the local security model to get a deeper narrative analysis.");
        out
    }
}

pub struct ModelStatus {
    pub present: bool,
    pub path: PathBuf,
    pub backend: &'static str,
}

/// Look for a bundled/downloaded GGUF model under the data dir.
pub fn detect(ctx: &Context) -> ModelStatus {
    let dir = ctx.model_dir();
    let present = std::fs::read_dir(&dir)
        .map(|mut e| e.any(|f| {
            f.ok()
                .map(|f| f.path().extension().is_some_and(|x| x == "gguf"))
                .unwrap_or(false)
        }))
        .unwrap_or(false);

    ModelStatus {
        present,
        path: dir,
        backend: if present { "llama.cpp (local)" } else { "heuristic fallback" },
    }
}

/// Return the active model. Today this is always the heuristic fallback; once a
/// GGUF is detected, swap in the llama.cpp-backed implementation here.
pub fn active(_ctx: &Context) -> Box<dyn LocalModel> {
    Box::new(HeuristicModel)
}
