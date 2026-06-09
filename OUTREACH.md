# REO — First-Customer Outreach Kit

Cold templates for the first 10 customers (see `COMPANY.md` for the ICP). Keep
them short, lead with the sovereignty + ransomware angle, and ask for a 15-min
call or a free pilot — not a sale.

> Replace `[…]` before sending. Send from a real domain (you have `chatapi.run`).
> Send 10–20/day, personalized in the first line. Track replies in a spreadsheet.

---

## 1. MSP (Managed Service Provider) — your best channel
**Subject:** ransomware protection your clients' data never leaves

> Hi [Name],
>
> You manage security for [N] SMB clients — and every EDR you deploy ships their
> files and telemetry to a vendor cloud. That's a liability you carry.
>
> We built REO: ransomware detection + auto-response that runs **entirely on the
> endpoint**. It catches encryption mid-attack, identifies the process, and kills
> it — with **zero data leaving the machine**. Flat ~$25–40/endpoint/yr, no
> data-volume billing.
>
> Worth 15 minutes? I'll set up a free pilot on a handful of your endpoints and
> show you a live ransomware-kill demo.
>
> — [You], REO

---

## 2. Privacy / residency-bound SMB (clinic, law/accounting firm, defense sub)
**Subject:** endpoint security that keeps your data in-house

> Hi [Name],
>
> For [clinic/firm], client data leaving your control isn't an option — but every
> mainstream security tool sends telemetry to a vendor's cloud.
>
> REO is endpoint protection that runs **100% on your machines**. It stops
> ransomware on the device (detect → kill the process), and nothing is ever
> uploaded. Built exactly for orgs with data-residency obligations.
>
> Can I show you a 10-minute live demo this week? Happy to run a free pilot on a
> couple of machines first.
>
> — [You]

---

## 3. Design-partner ask (warm/technical contact)
**Subject:** want to be a REO design partner?

> Hey [Name],
>
> I'm building REO — local-first ransomware protection that never sends data to a
> cloud (the anti-CrowdStrike on privacy + price). The detection engine works
> today; I'm looking for 3 design partners to deploy it on real machines and tell
> me what's missing.
>
> Free for the pilot, you get direct input on the roadmap (and locked-in early
> pricing). 20-minute call to set it up?
>
> — [You]

---

## 4. LinkedIn DM (short)
> Hi [Name] — building REO: ransomware detection + auto-response that runs
> entirely on the endpoint, no data shipped to a cloud. Given [their role/company],
> thought it might be relevant. Open to a quick demo? 🔒

---

## 5. Follow-up (3–4 days later, reply to your own thread)
> Hi [Name] — bumping this in case it slipped. The one-line pitch: CrowdStrike-grade
> ransomware protection, your data never leaves the machine, a fraction of the price.
> Even if it's not a fit, a 10-min look might be useful for how you think about
> data-residency in your stack. Worth a quick call?

---

## Demo script (15 min)
1. **Install** in one line (`irm … | iex`). "That's the whole deploy."
2. **`reo detect`** on their machine → clean result, 0 false positives. "On-device, nothing uploaded."
3. **Live kill:** run `reo watch --respond` on a test folder, trigger a simulated
   encryption → watch it detect the burst, name the process, and terminate it.
4. **The close:** "Same protection, your data never leaves, ~$25–40/endpoint. Want
   a free pilot on 5 machines this week?"
