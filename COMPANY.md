# REO — Company Operating Plan

> The one line: **"CrowdStrike-grade protection that never sends your data to
> anyone — at a fraction of the price."** Sovereign, local-first endpoint
> security and management.

This is the plan to turn the working product into a company. The product is
real (detect → attribute → kill ransomware, on-device, shipped). What follows is
the business around it.

---

## 1. Why now (the tailwinds)
- **Data sovereignty is exploding** — EU regulation, regulated industries
  (health/finance/defense/legal), and AI-era data paranoia. Orgs increasingly
  *cannot* send telemetry to a US vendor cloud.
- **Incumbents are architecturally cloud-ingestion** — CrowdStrike, SentinelOne,
  Datadog, Splunk all pull customer data into *their* cloud. They cannot promise
  "your data never leaves" without rebuilding their product.
- **Ransomware is the #1 SMB security fear**, and existing EDR is too expensive
  and complex for SMB/mid-market.
- **LLMs make conversational security/infra real** (your `infra` + NL surface).

## 2. The moat (what's defensible)
1. **Architecture.** Local-first detection + response. Incumbents can't match the
   privacy promise without re-architecting their whole business.
2. **Cost structure.** No data ingestion ⇒ ~zero marginal cost ⇒ you undercut
   pay-by-data-volume incumbents and *still* have fat margins.
3. **Already built + proven.** On-device ransomware detection that catches
   encryption mid-attack, names the process, and kills it — zero data uploaded.

## 3. Who buys first (ICP) — do NOT chase the Fortune 500 yet
F500 needs SOC 2/FedRAMP and 12-month sales cycles. Start where the pain + the
sovereignty angle are sharpest and the cycle is short:
1. **MSPs (Managed Service Providers)** — they deploy security across dozens of
   SMB clients. One MSP = many endpoints. **Best channel.**
2. **Privacy/residency-bound SMB & mid-market** — healthcare clinics, law &
   accounting firms, defense subcontractors, EU companies under GDPR.
3. **Ransomware-scared SMBs** priced out of CrowdStrike's cost + complexity.

## 4. Packaging & pricing
- **Consumer funnel (already built):** Free (shrink/clean/find/scan + free
  ransomware scan) → Basic/Premium/Advanced. The hook that builds trust + list.
- **Business (build next):** per-endpoint/year, **~$25–40/endpoint/yr** vs
  CrowdStrike's $60–185. Volume discounts for MSPs.
- **Enterprise (already scaffolded):** the `infra` Digital Data Center tier +
  fleet console + custom terms.

## 5. Go-to-market — the first 10 customers
- **Founder-led sales.** No GTM team yet.
- **Free ransomware scan as the wedge** — zero-friction trust builder; it's the
  consumer hook that lands the buyer.
- **Outreach to 50 MSPs + privacy-bound SMBs**; convert 2–3 **design partners**
  (free → paid, in exchange for feedback + a logo).
- **Content angle:** *"Your EDR ships your files to a vendor cloud. Ours doesn't."*
- **Land small (a team), expand to the fleet.**

## 6. Product roadmap to enterprise-grade (in priority order)
1. **Always-on service** — auto-start at boot (Windows Service / launchd /
   systemd). Turns `watch` into real protection.
2. **Fleet console** — a *privacy-preserving* backend: agents report **alerts,
   not data** to a central dashboard. **This is the key build for selling to
   businesses** — it's how you protect 10,000 endpoints without betraying the
   sovereignty promise.
3. **More detection classes** — credential theft, persistence, lateral movement.
4. **Kernel ETW / eBPF / ESF attribution** — ground-truth per-write process
   attribution (deeper than today's disk-I/O heuristic).
5. **SOC 2 Type II** — unlocks the bigger, compliance-bound customers.

## 7. Fundraising
- **Bootstrap path:** MSP/SMB revenue funds the build. Slower; you keep control.
- **Raise path:** with the working product + the sovereignty thesis + 3 paying
  design partners → **pre-seed/seed $750K–$2M.** Use of funds: build the fleet
  console + 2 engineers + 1 GTM. Pitch: *"the privacy-first, cost-disruptive
  CrowdStrike."* (See `PITCH.md`.)

## 8. What ONLY YOU can do (a terminal can't)
- **Incorporate** — Stripe Atlas → Delaware C-corp if raising US VC (or a local
  entity if bootstrapping).
- **Business bank account.**
- **Land the first 3 design-partner customers.**
- **Pitch & raise** from investors.
- **Hire** (first hire: a systems engineer for the fleet backend + kernel
  telemetry, or a founding GTM person).

## 9. Honest risks
- Giants with huge budgets and brand recognition.
- The detection engine must mature **beyond ransomware** to be a full EDR.
- Enterprise revenue is gated on **compliance** (months of audit).
- **Solo founder** — you need a team for the backend + GTM to go big.

## 10. First 30 days (concrete)
- **Week 1:** incorporate; polish the free ransomware scan as the public hook;
  ship the always-on service install.
- **Week 2:** build the fleet-console MVP (agents → alerts → dashboard).
- **Week 3:** outreach to 50 MSPs + privacy-bound SMBs; line up 3 design partners.
- **Week 4:** convert 1 design partner to paid; use the logo + traction to start
  raising (or reinvest the revenue).
