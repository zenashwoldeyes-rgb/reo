//! Local inference layer — REO's "AI security engineer" brain.
//!
//! When a local **Ollama** model is available, REO reasons about findings
//! through it for real, plain-language analysis — and every byte of that
//! inference stays on the machine (loopback to localhost; nothing is sent to any
//! vendor). When Ollama isn't running, REO falls back to a deterministic
//! template engine so it's still useful with zero setup. Either way: on-device.

use crate::config::Context;
use std::path::PathBuf;
use std::time::Duration;

pub trait LocalModel {
    /// Turn a topic plus observed facts into a plain-language explanation.
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
        out.push_str("Run a local model with Ollama for a deeper narrative analysis.");
        out
    }
}

/// On-device AI via a local Ollama model. All inference is local (loopback).
pub struct OllamaModel {
    model: String,
}

impl LocalModel for OllamaModel {
    fn narrate(&self, topic: &str, facts: &[String]) -> String {
        if facts.is_empty() {
            return format!("On {topic}: nothing notable stood out.");
        }
        let findings = facts
            .iter()
            .map(|f| format!("- {f}"))
            .collect::<Vec<_>>()
            .join("\n");
        let prompt = format!(
            "You are REO, a local security engineer talking to a non-technical person. \
             A scan of their computer surfaced these findings about {topic}:\n{findings}\n\n\
             In 3-5 short, calm, plain-English sentences: explain what this means, how worried \
             they should be, and the single most useful next step. Be specific. Do NOT invent \
             findings beyond the list above. No preamble."
        );
        match query_ollama(&self.model, &prompt) {
            Some(text) if !text.trim().is_empty() => text.trim().to_string(),
            // Inference failed (model busy, stopped) — degrade gracefully.
            _ => HeuristicModel.narrate(topic, facts),
        }
    }
}

/// One non-streaming generation against the local Ollama HTTP API.
fn query_ollama(model: &str, prompt: &str) -> Option<String> {
    let resp = ureq::post("http://127.0.0.1:11434/api/generate")
        .timeout(Duration::from_secs(90))
        .send_json(ureq::json!({ "model": model, "prompt": prompt, "stream": false }))
        .ok()?;
    let body: serde_json::Value = resp.into_json().ok()?;
    body["response"].as_str().map(|s| s.to_string())
}

/// If a local Ollama is up with a usable text model, return its name. Cheap when
/// Ollama is down: connecting to a closed localhost port is refused instantly.
fn ollama_model() -> Option<String> {
    let resp = ureq::get("http://127.0.0.1:11434/api/tags")
        .timeout(Duration::from_secs(2))
        .call()
        .ok()?;
    let body: serde_json::Value = resp.into_json().ok()?;
    let models = body["models"].as_array()?;
    let names = || models.iter().filter_map(|m| m["name"].as_str());
    // Prefer a plain text model; skip vision/embedding variants.
    names()
        .find(|n| !n.contains("vision") && !n.contains("embed"))
        .or_else(|| names().next())
        .map(|s| s.to_string())
}

pub struct ModelStatus {
    pub present: bool,
    pub path: PathBuf,
    pub backend: String,
}

/// Report the active inference backend: local Ollama if reachable, else a
/// bundled GGUF if present, else the heuristic fallback.
pub fn detect(ctx: &Context) -> ModelStatus {
    let dir = ctx.model_dir();
    if let Some(model) = ollama_model() {
        return ModelStatus {
            present: true,
            path: dir,
            backend: format!("ollama: {model} (local AI)"),
        };
    }
    let gguf = std::fs::read_dir(&dir)
        .map(|mut e| {
            e.any(|f| {
                f.ok()
                    .map(|f| f.path().extension().is_some_and(|x| x == "gguf"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    ModelStatus {
        present: gguf,
        path: dir,
        backend: if gguf { "llama.cpp (local)".into() } else { "heuristic fallback".into() },
    }
}

/// The active model: the local Ollama brain when available, else the heuristic.
pub fn active(_ctx: &Context) -> Box<dyn LocalModel> {
    match ollama_model() {
        Some(model) => Box::new(OllamaModel { model }),
        None => Box::new(HeuristicModel),
    }
}
