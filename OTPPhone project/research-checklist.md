# OTPPhone Research Checklist

## Market Feasibility

- [ ] **Demand validation** — Find a marketing/business contact who can independently test whether real demand exists in target segments (military, diplomatic, journalistic). Investor case is hollow without this.
- [ ] **Current military comms landscape** — Document what systems militaries actually use today, what fails, and what OTPPhone does better. Must be frameable for a non-technical procurement reader. Chase Cameron's army-comms contact re: all-network SIM trial.
- [ ] **Competitor and prior-art map** — Study Signal, Briar, Meshtastic, Element/Matrix, Bundesmessenger, Olvid, Tchap, SimpleX, Cwtch. Position honestly relative to each. Note SimpleX/Cwtch for metadata resistance; Briar/Meshtastic for offline mesh.
- [ ] **Sovereign messaging precedents** — Verify and document: France (DINUM directive, Olvid, Tchap, Visio); Germany (Bundesmessenger on Matrix/Element, not Signal); historical UK OTP diplomatic/military use. Get facts precise before pitching.
- [ ] **Funding routes** — Review Y Combinator requirements. Scan government/defence tenders broad enough to fit. Understand the defence-prime acquisition path (Thales, Raytheon) as the realistic exit.
- [ ] **Regulatory risk of USDT wallet** — Clarify FCA exposure for a non-custodial crypto wallet inside the app. Do not assume non-custodial is a clean exemption.

---

## Tech Feasibility

- [ ] **Group-chat security model** — Resolve key distribution, revocation, and security properties for multi-party OTP before writing code. Pairwise pads vs. shared group pad; neither is free. Define exactly what security guarantee is being promised.
- [ ] **At-rest key model** — Decide where the AES-at-rest key lives (passphrase-derived vs. secure element/TEE). Write down the threat model for a device seized while powered off.
- [ ] **Metadata privacy** — Investigate mixnet/onion routing (Loopix/Nym) feasibility and cost. Study SimpleX (no persistent user identifiers) and Cwtch (Tor-based) as closest prior art. "Hide the social graph server-side" is a hard, named problem.
- [ ] **Capture/compromise failsafes** — Research how current military comms handle a captured operator (key zeroisation, frequency changes, remote wipe). Map gaps. Align with EncroChat-style wipe-on-power-on approach.
- [ ] **Offline/mesh feasibility** — Assess Meshtastic (LoRa, open source) for range and integration. Evaluate whether Starlink fallback is realistic for target customers. Check Briar (Bluetooth P2P) for short-range contested environments.
- [ ] **Hardware sourcing** — Source unlocked Android boards or a PinePhone that can be fully flashed. Confirm what can/cannot be locked down. Use Cameron's two rooted Nexus handsets as a free starting point.
