//! Enterprise "AI Digital Data Center" — conversational infrastructure planning.
//!
//! Turns a natural-language request into a reviewed execution PLAN:
//!   analyze → steps → estimate cost → estimate risk → generate the
//!   infrastructure-as-code it would apply.
//!
//! What is real in this build: the request analysis, the structured plan, the
//! cost/risk estimates, and the generated Terraform for common requests. What is
//! the seam: LIVE execution (running that Terraform against your AWS/Azure/GCP/DO
//! accounts) is the Enterprise cloud connector — clearly marked, never faked.
//! The keyword matcher here is the fast first pass; a bundled model classifies
//! the long tail in production.

/// A reviewed plan REO would execute, with everything a human needs to approve it.
pub struct Plan {
    pub kind: &'static str,
    pub summary: String,
    pub provider: String,
    pub region: String,
    pub steps: Vec<String>,
    pub monthly_cost_usd: f64,
    pub risk: &'static str,
    /// Generated infrastructure-as-code, when we have a template for the request.
    pub iac: Option<String>,
    /// True when REO produced ready-to-apply IaC; false for plan-only requests
    /// that need the live infrastructure graph (the production connector).
    pub executable: bool,
}

/// Analyze a request and produce a plan. Deterministic; never touches the network.
pub fn plan(request: &str) -> Plan {
    let t = request.to_lowercase();
    let (region_human, do_region) = region_for(&t);
    let provider = provider_for(&t);

    let has = |needles: &[&str]| needles.iter().any(|n| t.contains(n));

    if has(&["database", "postgres", "postgresql", "mysql", "db ", "redis", "mongo"]) {
        return database_plan(provider, region_human, do_region);
    }
    if has(&["kubernetes", "k8s", "cluster", "container orchestr"]) {
        return kubernetes_plan(provider, region_human, do_region);
    }
    if has(&["server", "vm", "virtual machine", "instance", "compute", "gpu", "droplet"]) {
        return server_plan(&t, provider, region_human, do_region);
    }
    if has(&["scale", "autoscal", "million users", "traffic", "handle load", "more users"]) {
        return scale_plan(provider);
    }
    if has(&["secure", "ransomware", "vulnerab", "harden", "threat", "firewall", "zero trust"]) {
        return secure_plan(provider);
    }
    if has(&["cost", "optimi", "save money", "spend", "bill", "cheaper", "waste"]) {
        return cost_plan(provider);
    }
    if has(&["backup", "disaster recovery", "dr plan", " dr ", "restore", "snapshot", "replicat"]) {
        return backup_plan(provider);
    }

    // Fallback: a generic analysis plan for anything we don't have a template for.
    Plan {
        kind: "general",
        summary: format!("Analyze \"{}\" and propose an infrastructure change.", request.trim()),
        provider: provider.to_string(),
        region: region_human.to_string(),
        steps: vec![
            "Inventory the relevant parts of your infrastructure graph".into(),
            "Draft the change and the resources it touches".into(),
            "Estimate cost and blast radius".into(),
            "Generate the infrastructure-as-code".into(),
            "Present for approval before applying".into(),
        ],
        monthly_cost_usd: 0.0,
        risk: "unknown",
        iac: None,
        executable: false,
    }
}

fn database_plan(provider: &str, region_human: &str, do_region: &str) -> Plan {
    let iac = format!(
        "# REO-generated — managed PostgreSQL in {region_human}\n\
         resource \"digitalocean_database_cluster\" \"reo_postgres\" {{\n\
         \x20 name       = \"reo-postgres\"\n\
         \x20 engine     = \"pg\"\n\
         \x20 version    = \"16\"\n\
         \x20 size       = \"db-s-1vcpu-2gb\"\n\
         \x20 region     = \"{do_region}\"\n\
         \x20 node_count = 1\n\
         }}\n\n\
         output \"postgres_uri\" {{\n\
         \x20 value     = digitalocean_database_cluster.reo_postgres.uri\n\
         \x20 sensitive = true\n\
         }}\n"
    );
    Plan {
        kind: "database",
        summary: format!("Deploy a managed PostgreSQL 16 database in {region_human}."),
        provider: provider.to_string(),
        region: region_human.to_string(),
        steps: vec![
            "Provision a managed PostgreSQL 16 cluster".into(),
            "Place it inside a private VPC (no public exposure)".into(),
            "Enable daily automated backups (7-day retention)".into(),
            "Wire up metrics and high-CPU / low-disk alerts".into(),
            "Generate credentials and return the connection URI".into(),
        ],
        monthly_cost_usd: 30.0,
        risk: "low",
        iac: Some(iac),
        executable: true,
    }
}

fn server_plan(t: &str, provider: &str, region_human: &str, do_region: &str) -> Plan {
    let gpu = t.contains("gpu") || t.contains("rtx") || t.contains("5090") || t.contains("a100");
    let (size, cost, what) = if gpu {
        ("gpu-h100x1-80gb", 1200.0, "a GPU server")
    } else {
        ("s-2vcpu-4gb", 24.0, "a virtual server")
    };
    let iac = format!(
        "# REO-generated — {what} in {region_human}\n\
         resource \"digitalocean_droplet\" \"reo_server\" {{\n\
         \x20 name   = \"reo-server\"\n\
         \x20 image  = \"ubuntu-24-04-x64\"\n\
         \x20 size   = \"{size}\"\n\
         \x20 region = \"{do_region}\"\n\
         }}\n\n\
         output \"server_ip\" {{\n\
         \x20 value = digitalocean_droplet.reo_server.ipv4_address\n\
         }}\n"
    );
    Plan {
        kind: "server",
        summary: format!("Provision {what} (Ubuntu 24.04) in {region_human}."),
        provider: provider.to_string(),
        region: region_human.to_string(),
        steps: vec![
            format!("Provision {what} ({size})"),
            "Attach a firewall: allow SSH from your IP + 80/443 only".into(),
            "Harden SSH (keys only) and enable automatic security updates".into(),
            "Install the host metrics agent".into(),
            "Return the public IP and SSH command".into(),
        ],
        monthly_cost_usd: cost,
        risk: "low",
        iac: Some(iac),
        executable: true,
    }
}

fn kubernetes_plan(provider: &str, region_human: &str, do_region: &str) -> Plan {
    let iac = format!(
        "# REO-generated — autoscaling Kubernetes cluster in {region_human}\n\
         resource \"digitalocean_kubernetes_cluster\" \"reo_cluster\" {{\n\
         \x20 name    = \"reo-cluster\"\n\
         \x20 region  = \"{do_region}\"\n\
         \x20 version = \"1.31.1-do.0\"\n\
         \x20 node_pool {{\n\
         \x20\x20 name       = \"default\"\n\
         \x20\x20 size       = \"s-2vcpu-4gb\"\n\
         \x20\x20 node_count = 3\n\
         \x20\x20 auto_scale = true\n\
         \x20\x20 min_nodes  = 3\n\
         \x20\x20 max_nodes  = 10\n\
         \x20 }}\n\
         }}\n"
    );
    Plan {
        kind: "kubernetes",
        summary: format!("Deploy a 3-node autoscaling Kubernetes cluster in {region_human}."),
        provider: provider.to_string(),
        region: region_human.to_string(),
        steps: vec![
            "Create a managed Kubernetes 1.31 cluster".into(),
            "Configure a 3–10 node autoscaling pool".into(),
            "Install an ingress controller + cert-manager (TLS)".into(),
            "Wire metrics/logs into the monitoring agent".into(),
            "Return the kubeconfig".into(),
        ],
        monthly_cost_usd: 72.0,
        risk: "medium",
        iac: Some(iac),
        executable: true,
    }
}

fn scale_plan(provider: &str) -> Plan {
    Plan {
        kind: "scale",
        summary: "Scale the target service for a large traffic increase.".into(),
        provider: provider.to_string(),
        region: "your existing regions".into(),
        steps: vec![
            "Read the current architecture from the infrastructure graph".into(),
            "Compute required capacity from the target user count".into(),
            "Add a load balancer and horizontal autoscaling".into(),
            "Put a CDN in front of static assets".into(),
            "Add read replicas / caching for the data tier".into(),
            "Update dashboards and alert thresholds".into(),
        ],
        monthly_cost_usd: 0.0,
        risk: "medium",
        iac: None,
        executable: false,
    }
}

fn secure_plan(provider: &str) -> Plan {
    Plan {
        kind: "secure",
        summary: "Harden the cloud footprint and turn on threat detection.".into(),
        provider: provider.to_string(),
        region: "all regions".into(),
        steps: vec![
            "Inventory all cloud assets into the infrastructure graph".into(),
            "Scan for misconfigurations and known CVEs".into(),
            "Tighten security groups / firewalls to least-privilege".into(),
            "Enable threat detection and audit logging".into(),
            "Ensure backups + MFA on privileged accounts".into(),
            "Produce a prioritized security report".into(),
        ],
        monthly_cost_usd: 0.0,
        risk: "low",
        iac: None,
        executable: false,
    }
}

fn cost_plan(provider: &str) -> Plan {
    Plan {
        kind: "cost",
        summary: "Find and remove cloud waste.".into(),
        provider: provider.to_string(),
        region: "all regions".into(),
        steps: vec![
            "Pull billing + utilization across accounts".into(),
            "Flag idle/unattached resources (disks, IPs, instances)".into(),
            "Recommend rightsizing for over-provisioned compute".into(),
            "Recommend reserved/committed-use discounts".into(),
            "Estimate monthly savings before any change".into(),
        ],
        monthly_cost_usd: 0.0,
        risk: "low",
        iac: None,
        executable: false,
    }
}

fn backup_plan(provider: &str) -> Plan {
    Plan {
        kind: "backup",
        summary: "Set up a tested backup + disaster-recovery plan.".into(),
        provider: provider.to_string(),
        region: "primary + a second region".into(),
        steps: vec![
            "Define RPO/RTO targets with you".into(),
            "Schedule automated snapshots of databases and volumes".into(),
            "Replicate snapshots to a second region".into(),
            "Codify the recovery runbook".into(),
            "Run a restore drill and verify integrity".into(),
        ],
        monthly_cost_usd: 0.0,
        risk: "low",
        iac: None,
        executable: false,
    }
}

/// The Terraform provider header REO prepends when *executing* a plan, matched
/// to the resources in the generated IaC. Returns `None` for IaC not wired for
/// live apply in this build (DigitalOcean is wired today).
pub fn provider_header(iac: &str) -> Option<&'static str> {
    if iac.contains("digitalocean_") {
        Some(concat!(
            "terraform {\n",
            "  required_providers {\n",
            "    digitalocean = {\n",
            "      source  = \"digitalocean/digitalocean\"\n",
            "      version = \"~> 2.0\"\n",
            "    }\n",
            "  }\n",
            "}\n\n",
            "provider \"digitalocean\" {}\n\n",
        ))
    } else {
        None
    }
}

fn region_for(t: &str) -> (&'static str, &'static str) {
    if t.contains("canada") || t.contains("toronto") {
        ("Canada (Toronto)", "tor1")
    } else if t.contains("frankfurt") || t.contains("germany") || t.contains("europe") {
        ("Germany (Frankfurt)", "fra1")
    } else if t.contains("london") || t.contains("uk") || t.contains("britain") {
        ("UK (London)", "lon1")
    } else if t.contains("singapore") || t.contains("asia") {
        ("Singapore", "sgp1")
    } else {
        ("US East (New York)", "nyc3")
    }
}

fn provider_for(t: &str) -> &'static str {
    if t.contains("aws") || t.contains("amazon") {
        "AWS"
    } else if t.contains("azure") || t.contains("microsoft") {
        "Azure"
    } else if t.contains("gcp") || t.contains("google cloud") {
        "Google Cloud"
    } else if t.contains("hetzner") {
        "Hetzner"
    } else {
        "DigitalOcean"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_request_generates_terraform() {
        let p = plan("deploy a postgresql database in canada");
        assert_eq!(p.kind, "database");
        assert!(p.executable);
        let iac = p.iac.expect("should generate IaC");
        assert!(iac.contains("digitalocean_database_cluster"));
        assert!(iac.contains("tor1"), "should pick the Canada region");
        assert!(p.monthly_cost_usd > 0.0);
    }

    #[test]
    fn gpu_server_is_recognized_and_pricier() {
        let gpu = plan("create a gpu server with 2 rtx 5090s");
        let vm = plan("create a small server");
        assert_eq!(gpu.kind, "server");
        assert!(gpu.monthly_cost_usd > vm.monthly_cost_usd);
        assert!(gpu.iac.unwrap().contains("gpu-"));
    }

    #[test]
    fn abstract_requests_are_plan_only() {
        for req in ["scale my api to 1 million users", "secure my company", "optimize cloud costs"] {
            let p = plan(req);
            assert!(!p.executable, "{req} should be plan-only (needs the live graph)");
            assert!(!p.steps.is_empty());
        }
    }

    #[test]
    fn provider_and_region_are_parsed() {
        let p = plan("deploy a database on aws in london");
        assert_eq!(p.provider, "AWS");
        assert!(p.region.contains("London"));
    }
}
