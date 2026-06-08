//! Shared scan vocabulary: findings, severities, and the aggregated report.

use crate::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Map a 0–100 risk score onto a severity band.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=14 => Severity::Info,
            15..=34 => Severity::Low,
            35..=59 => Severity::Medium,
            60..=84 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// A single thing REO noticed. Findings carry their own evidence so the report
/// is explainable — "what it looks like and why" — not just a score.
#[derive(Debug, Clone)]
pub struct Finding {
    pub category: String,
    pub title: String,
    pub detail: String,
    pub score: u8,
    pub evidence: Vec<String>,
    pub recommendation: Option<String>,
}

impl Finding {
    pub fn new(category: &str, title: &str, detail: &str, score: u8) -> Self {
        Finding {
            category: category.to_string(),
            title: title.to_string(),
            detail: detail.to_string(),
            score,
            evidence: Vec::new(),
            recommendation: None,
        }
    }

    pub fn evidence(mut self, line: impl Into<String>) -> Self {
        self.evidence.push(line.into());
        self
    }

    pub fn recommend(mut self, rec: &str) -> Self {
        self.recommendation = Some(rec.to_string());
        self
    }

    pub fn severity(&self) -> Severity {
        Severity::from_score(self.score)
    }
}

/// The aggregated result of a scan, ready to print as a structured report.
#[derive(Debug, Default)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    /// Human-readable counts per section, e.g. ("processes", "147 scanned").
    pub sections: Vec<(String, String)>,
}

impl ScanReport {
    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn note_section(&mut self, name: &str, summary: &str) {
        self.sections.push((name.to_string(), summary.to_string()));
    }

    /// Overall risk = the worst finding, nudged up when many issues stack.
    pub fn overall_score(&self) -> u8 {
        let max = self.findings.iter().map(|f| f.score).max().unwrap_or(0);
        let stacking = (self.findings.len().saturating_sub(1) as u8).min(10);
        max.saturating_add(stacking).min(100)
    }

    /// Print the full structured terminal report.
    pub fn print(&self) {
        ui::section("Scan coverage");
        for (name, summary) in &self.sections {
            ui::kv(name, summary);
        }

        let mut findings = self.findings.clone();
        findings.sort_by(|a, b| b.score.cmp(&a.score));

        ui::section(&format!("Findings ({})", findings.len()));
        if findings.is_empty() {
            ui::success("Nothing suspicious surfaced. Your machine looks clean.");
        } else {
            for f in &findings {
                println!();
                println!("   {}", ui::risk_bar(f.score, f.severity().label()));
                ui::kv("what", &f.title);
                ui::kv("where", &f.category);
                ui::kv("detail", &f.detail);
                for ev in &f.evidence {
                    ui::kv("evidence", ev);
                }
                if let Some(rec) = &f.recommendation {
                    ui::kv("fix", rec);
                }
            }
        }

        ui::section("Overall risk");
        let score = self.overall_score();
        println!("   {}", ui::risk_bar(score, Severity::from_score(score).label()));
    }
}
