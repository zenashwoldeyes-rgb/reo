# REO — SOC 2 Readiness Checklist

> **The honest part:** I can give you the readiness map and the policy list — but
> SOC 2 is **not code**. It's an independent **audit** by a licensed CPA firm of
> how your company actually operates, over a window of time. Realistically:
> **~3–6 months and ~$15k–$50k** (Type I is a point-in-time snapshot; Type II
> observes controls over 3–12 months and is what enterprises actually ask for).
> Don't start this until you have paying customers asking for it — it's a sales
> unlock, not a day-one task.

## How it actually works
1. Pick a **compliance-automation platform** — **Vanta** or **Drata** (~$7k–$15k/yr).
   They auto-collect evidence from your cloud/HR/code and track controls. This is
   the single biggest time-saver; nearly every startup uses one.
2. Connect your stack (GitHub, cloud, identity provider, HR).
3. Write the **policies** (templates below; the platform provides them).
4. Run controls for the observation window (Type II).
5. A **third-party CPA firm** performs the audit and issues the report.

## The five Trust Service Criteria
You almost always scope to **Security** (required) first; add the others as
customers demand them.
- **Security** (required) — protect against unauthorized access.
- **Availability** — system uptime/SLAs.
- **Processing Integrity** — processing is complete/accurate.
- **Confidentiality** — confidential data is protected.
- **Privacy** — personal data handled per policy.

> REO's architecture is a **head start here**: "customer data never leaves their
> machine" makes Confidentiality/Privacy dramatically easier to attest — you're
> not storing their data at all. Lean on that in the audit and the sales pitch.

## Controls checklist (Security scope)
- [ ] **Access control** — SSO + MFA on every system; least-privilege; quarterly
      access reviews; offboarding revokes access same-day.
- [ ] **Endpoint security** — company laptops have disk encryption, screen lock,
      and… an EDR (you literally make one).
- [ ] **Code & change management** — PRs require review; CI runs tests; protected
      `main` branch; no secrets in the repo.
- [ ] **Vulnerability management** — dependency scanning (Dependabot), a patch SLA.
- [ ] **Logging & monitoring** — audit logs for production systems; alerting.
- [ ] **Encryption** — TLS in transit; encryption at rest for any stored data.
- [ ] **Vendor management** — list of sub-processors; review their SOC 2s.
- [ ] **Incident response** — a written IR plan; a way to detect + report incidents.
- [ ] **Business continuity / backups** — backups tested; a recovery plan.
- [ ] **HR security** — background checks; security-awareness training; signed
      acceptable-use policy.

## Policies you'll need (the platform gives templates)
Information Security · Access Control · Acceptable Use · Change Management ·
Incident Response · Business Continuity / DR · Vendor Management · Risk
Assessment · Data Classification · Encryption · Vulnerability Management · HR
Security.

## Recommended sequence
1. **Now (free, do today):** turn on branch protection + required PR reviews +
   Dependabot on the repo; enable MFA everywhere; encrypt your laptop. These are
   real security wins regardless of audit.
2. **When a customer asks:** buy Vanta/Drata, connect your stack, adopt policies.
3. **3–6 months later:** engage a CPA firm, complete the Type II audit, get the
   report — then put the badge on the site and unlock the customers who required it.

> FedRAMP (for US federal customers) is a far heavier, longer, costlier process —
> don't touch it until you have federal demand and the revenue to fund it.
