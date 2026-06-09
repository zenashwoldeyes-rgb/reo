//! Natural-language intent routing.
//!
//! The REPL accepts free text. In production the local model classifies intent;
//! here we use a fast keyword router that covers the documented phrasings and
//! degrades gracefully to `Unknown` (which the shell turns into a help nudge).
//! The same router is the deterministic first pass even when a model is present,
//! so common commands never wait on inference.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Scan,
    Network,
    Investigate,
    Remove,
    Slow,
    Lockdown,
    Timeline,
    Shrink(Vec<String>),
    ShrinkAll,
    Clean,
    Space,
    Find(String),
    Infra(String),
    Pii,
    Protect,
    Plans,
    Upgrade,
    Activate(Option<String>),
    Renew,
    Status,
    Privacy,
    Help,
    Quit,
    Unknown(String),
}

/// Words to drop when extracting file arguments from a "shrink …" phrase, so
/// "shrink my file logo.png please" yields just `logo.png`.
const SHRINK_STOPWORDS: &[&str] = &[
    "shrink", "compress", "make", "smaller", "size", "down", "this", "that", "the", "my", "a",
    "file", "files", "please", "for", "me", "to",
];

pub fn route(input: &str) -> Intent {
    let t = input.trim().to_lowercase();
    if t.is_empty() {
        return Intent::Unknown(String::new());
    }

    // Exact/leading commands first.
    match t.as_str() {
        "exit" | "quit" | ":q" | "q" => return Intent::Quit,
        "help" | "?" | "commands" => return Intent::Help,
        "scan" => return Intent::Scan,
        "status" => return Intent::Status,
        "upgrade" | "pro" => return Intent::Upgrade,
        "renew" => return Intent::Renew,
        "lockdown" => return Intent::Lockdown,
        "privacy" => return Intent::Privacy,
        "plans" | "pricing" | "price" | "cost" => return Intent::Plans,
        _ => {}
    }

    // Activate carries a signed token that is case-sensitive (base64url), so it
    // is detected before the lowercase keyword chain to preserve the token.
    if t.starts_with("activate") || t.starts_with("redeem") {
        let token = input
            .split_whitespace()
            .find(|w| w.starts_with("REO1."))
            .map(|s| s.to_string());
        return Intent::Activate(token);
    }

    // Enterprise: cloud infrastructure requests carry a free-text spec. Detect
    // the clear infra verbs before the local-security keyword chain so they go
    // to the Digital Data Center, not the local machine.
    if t.starts_with("deploy")
        || t.starts_with("provision")
        || t.starts_with("spin up")
        || t.contains("create a database")
        || t.contains("create a server")
        || t.contains("create a vm")
        || t.contains("create a gpu")
        || t.contains("kubernetes")
        || t.contains("k8s")
        || t.contains("scale my")
        || t.contains("disaster recovery")
        || (t.contains("optimize") && (t.contains("cloud") || t.contains("cost")))
        || (t.contains("secure my") && (t.contains("company") || t.contains("infrastructure") || t.contains("cloud")))
    {
        return Intent::Infra(input.trim().to_string());
    }

    // Find carries a free-text query; detect it before the keyword chain and
    // hand the whole phrase to the search (it strips filler words itself).
    if t.starts_with("find") || t.starts_with("search") || t.starts_with("locate")
        || t.contains("where is") || t.contains("where are")
    {
        return Intent::Find(input.trim().to_string());
    }

    // "Shrink everything / all my photos / make my computer smaller" optimizes
    // images computer-wide — detect it before the per-file shrink below.
    let shrink_verb = t.starts_with("shrink")
        || t.starts_with("compress")
        || t.contains("optimize")
        || (t.contains("make") && t.contains("smaller"));
    let broad_scope = t.contains("everything")
        || t.contains("all my")
        || t.contains(" all ")
        || t.starts_with("all ")
        || t.contains("whole computer")
        || t.contains("my computer")
        || t.contains("my photos")
        || t.contains("my pictures")
        || t.contains("my images");
    if shrink_verb && broad_scope {
        return Intent::ShrinkAll;
    }

    // Shrink needs its file arguments preserved in original case, so it is
    // detected before the lowercase keyword chain.
    if t.starts_with("shrink") || t.starts_with("compress") || (t.contains("make") && t.contains("smaller")) {
        let args: Vec<String> = input
            .split_whitespace()
            .filter(|tok| !SHRINK_STOPWORDS.contains(&tok.to_lowercase().as_str()))
            .map(|s| s.to_string())
            .collect();
        return Intent::Shrink(args);
    }

    let has = |needles: &[&str]| needles.iter().any(|n| t.contains(n));

    if has(&["plans", "pricing", "how much", "what does it cost", "what's the price"]) {
        Intent::Plans
    } else if has(&["go pro", "upgrade", "buy pro", "i want pro", "purchase", "go basic", "go premium", "go advanced"]) {
        Intent::Upgrade
    } else if has(&["renew", "extend my license", "extend license"]) {
        Intent::Renew
    } else if has(&["personal info", "personal information", "my secrets", "exposed credentials", "find my pii", "leaked"]) {
        Intent::Pii
    } else if has(&["identity protection", "protect my identity", "info removal", "identity insurance", "financial protection"]) {
        Intent::Protect
    } else if has(&["lock", "harden", "lock down", "secure my machine", "close ports"]) {
        Intent::Lockdown
    } else if has(&["biggest file", "biggest files", "largest file", "largest files", "big files", "taking up space", "taking up my space", "what's taking up", "whats taking up", "using my disk", "disk usage", "eating my disk", "space hog"]) {
        Intent::Space
    } else if has(&["clean", "cleaner", "free up space", "free space", "junk", "tidy", "disk space", "reclaim", "temp files", "temporary files"]) {
        Intent::Clean
    } else if has(&["remove", "get rid of", "delete the", "kill the", "remediate", "adware", "malware"]) {
        Intent::Remove
    } else if has(&["network", "connections", "phoning home", "phone home", "what's running on my net"]) {
        Intent::Network
    } else if has(&["investigate", "something feels off", "feels off", "something is wrong", "behavioral"]) {
        Intent::Investigate
    } else if has(&["last night", "happened", "timeline", "logs", "overnight", "what changed"]) {
        Intent::Timeline
    } else if has(&["slow", "sluggish", "laggy", "why is my machine", "speed up", "performance"]) {
        Intent::Slow
    } else if has(&["scan", "check my", "is my computer", "am i infected", "look for malware", "full scan"]) {
        Intent::Scan
    } else if has(&["privacy", "do you phone home", "air gap", "air-gap", "send my data"]) {
        Intent::Privacy
    } else if has(&["license", "subscription", "version", "model status"]) {
        Intent::Status
    } else {
        Intent::Unknown(input.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_documented_phrasings() {
        assert_eq!(route("scan my computer"), Intent::Scan);
        assert_eq!(route("what's running on my network right now"), Intent::Network);
        assert_eq!(route("something feels off, investigate"), Intent::Investigate);
        assert_eq!(route("remove the adware"), Intent::Remove);
        assert_eq!(route("why is my machine slow"), Intent::Slow);
        assert_eq!(route("show me everything that happened last night"), Intent::Timeline);
        assert_eq!(route("lock this machine down"), Intent::Lockdown);
        assert_eq!(route("I want to go Pro"), Intent::Upgrade);
    }

    #[test]
    fn bare_commands_and_quit() {
        assert_eq!(route("status"), Intent::Status);
        assert_eq!(route("exit"), Intent::Quit);
        assert_eq!(route("quit"), Intent::Quit);
        assert_eq!(route("help"), Intent::Help);
    }

    #[test]
    fn unknown_preserves_original_text() {
        assert_eq!(
            route("teach me to juggle"),
            Intent::Unknown("teach me to juggle".to_string())
        );
    }

    #[test]
    fn shrink_extracts_file_args_in_original_case() {
        assert_eq!(
            route("shrink my file Logo.PNG please"),
            Intent::Shrink(vec!["Logo.PNG".to_string()])
        );
        assert_eq!(route("compress report.csv"), Intent::Shrink(vec!["report.csv".to_string()]));
        assert_eq!(route("shrink"), Intent::Shrink(vec![]));
    }

    #[test]
    fn shrink_all_routes_for_broad_phrases() {
        assert_eq!(route("shrink everything"), Intent::ShrinkAll);
        assert_eq!(route("shrink all my photos"), Intent::ShrinkAll);
        assert_eq!(route("make my computer smaller"), Intent::ShrinkAll);
        assert_eq!(route("optimize all my pictures"), Intent::ShrinkAll);
        // A specific file should still be a per-file shrink, not all.
        assert_eq!(route("shrink logo.png"), Intent::Shrink(vec!["logo.png".to_string()]));
    }

    #[test]
    fn activate_captures_token_in_original_case() {
        assert_eq!(
            route("activate REO1.aBcD.eFgH"),
            Intent::Activate(Some("REO1.aBcD.eFgH".to_string()))
        );
        assert_eq!(route("activate"), Intent::Activate(None));
    }

    #[test]
    fn pricing_and_tier_intents() {
        assert_eq!(route("plans"), Intent::Plans);
        assert_eq!(route("how much does this cost"), Intent::Plans);
        assert_eq!(route("scan for my personal info"), Intent::Pii);
        assert_eq!(route("protect my identity"), Intent::Protect);
    }
}
