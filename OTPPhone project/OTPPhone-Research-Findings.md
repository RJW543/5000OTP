# OTPPhone Research Findings

**Prepared:** 5 June 2026
**Scope:** Desk research against the OTPPhone research checklist (Market Feasibility and Tech Feasibility).
**Stance:** Comprehensive and balanced. Findings and trade-offs are set out so that conclusions remain yours.
**Method:** Primary sources (UK GOV.UK and FCA publications, IETF RFCs, vendor and project documentation) supplemented by reputable secondary reporting. Key links are listed under Sources at the end.

> Two checklist items (demand validation, and the all-network SIM trial via Cameron's contact) require human action rather than desk research. They are flagged in place and summarised under Action Items.
>
> FCA matters are a legal question. This document is research, not legal advice; it should be confirmed with a specialist adviser before launch.

---

## Part 1: Market Feasibility

### 1. Demand validation (action item, not desk research)

The checklist is right that the investor case is hollow without independent evidence of demand, and this cannot be manufactured at a desk. Public signals (sovereign-messaging mandates in France and Germany, sustained defence-comms budgets, the Ukraine-driven interest in resilient communications) indicate institutional appetite for sovereign secure communications, but that is not the same as validated demand for *this* product at a price that supports a business.

The three target segments behave very differently as buyers. Militaries procure over multi-year cycles through accredited channels and primes. Diplomatic and government users buy through central IT and security authorities (the French and German precedents are government-led, not bottom-up). Journalists and the NGOs that equip them have little or no budget and tend to adopt free tools (Signal, Briar). A single product pitched at all three will meet three incompatible buying processes.

**Recommendation:** commission structured customer-discovery interviews through a business or marketing contact, segment by segment, before further engineering spend. Treat journalist adoption as a credibility and distribution play rather than a revenue line.

### 2. Current military communications landscape

Modern military communications are layered. At the tactical edge, combat-net radios carry voice and data: the UK uses Bowman, with a slow transition to Morpheus under the LETacCIS programme. Mobile ad-hoc network (MANET) radios provide self-forming mesh. Satellite communications provide reach-back. At the application layer, the Android Team Awareness Kit (ATAK) running on end-user devices has become the de facto standard for situational awareness, tactical chat and data sharing across US SOCOM and allied special forces. Hardened smartphones exist: Samsung's Galaxy Tactical Edition with Knox holds NIAP and CSfC dual-layer certifications for handling classified data up to Top Secret.

**What fails.** The UK's Morpheus programme is badly delayed. Bowman's out-of-service date has slipped from 2026 to somewhere between 2031 and 2035, and the General Dynamics UK "Evolve to Open" transition contract (worth around £395 million) was terminated in December 2023. Tactical communications are heavy, costly and procured slowly. The Ukraine war has shown that commercial kit (Starlink, ATAK, Android handsets) is used heavily but creates electromagnetic signatures and geolocation risk.

**Where OTPPhone fits, framed for a procurement reader.** OTPPhone is an application-and-handset product that rides existing bearers (cellular, wifi, satellite), not a tactical radio or a waveform. It therefore competes at the secure-messaging and end-user-device layer (the ATAK ecosystem, hardened-smartphone messengers, and sovereign messengers such as Olvid and the Matrix-based government apps), not at the radio-bearer layer. Honest positioning avoids implying it replaces Bowman or a MANET radio. Its credible differentiators are sovereign control, strong at-rest protection and capture failsafes on a dedicated handset, rather than "encryption" as such, which is already commoditised.

**Action:** chase Cameron's army-comms contact regarding the all-network SIM trial. A multi-network roaming SIM is a bearer-availability feature (useful for resilience) and is separable from the cryptographic design.

### 3. Competitor and prior-art map

The honest summary is that both spaces OTPPhone would enter, metadata-resistant messaging and sovereign secure messaging, are already occupied by capable and in some cases government-certified products.

**Signal.** Centralised, widely regarded as the gold standard for end-to-end content encryption (the Signal Protocol with the double ratchet). It historically required a phone number and added usernames in 2024 to reduce phone-number exposure. "Sealed sender" hides the sender from the server, but the server still sees IP and timing, and registration remains a metadata anchor. US non-profit, US-hosted, not sovereign. Open source.

**Briar.** Peer-to-peer with no central server; Tor when online, Bluetooth, wifi or memory card when offline. Strong for contested short-range and censored environments. Text only, no voice, small groups, with battery and usability constraints. Built on the Bramble protocol.

**Meshtastic.** LoRa mesh, open source. Very long radio range (single hop up to roughly 16 km in line of sight, mesh relaying quoted at 70 to 150 km) but extremely low bandwidth and text only, and it congests when many users transmit. A last-resort bearer for tiny messages, not a primary channel.

**Element / Matrix.** A federated protocol with end-to-end encryption (Olm and Megolm). It is the foundation for the sovereign deployments below. Membership and timing metadata are more exposed than in SimpleX or Cwtch, but self-hosting and federation make it the leading choice for digital sovereignty.

**BwMessenger and BundesMessenger (Germany).** Matrix-based messengers built by BWI with Element. BwMessenger has run for the Bundeswehr since November 2020 with more than 100,000 users; BundesMessenger, for wider public administration, was released in December 2023. A clear case of a government choosing Matrix and Element over Signal for sovereignty.

**Olvid (France).** ANSSI-certified (CSPN; iOS in 2020, Android in 2021), with no central directory of users, encrypted metadata, and double-ratchet forward secrecy. Mandated for French government use from December 2023. This is the closest commercial precedent for a sovereign secure messenger.

**Tchap (France).** The French civil-service messenger, built on Matrix by DINUM with ANSSI input and hosted on Interior Ministry servers.

**SimpleX.** Operates with no user identifiers of any kind, not even random ones, using temporary pairwise identifiers for message queues. There is no persistent identity to anchor a social graph, so servers cannot correlate a user's contacts. The closest prior art for hiding who talks to whom.

**Cwtch.** Decentralised, metadata-resistant group messaging over Tor v3 onion services, from the Open Privacy Research Society. Alongside SimpleX, the closest prior art for metadata resistance.

**Positioning conclusion (for you to weigh).** Differentiation cannot rest on "encrypted messaging" alone. A defensible position would combine a hardened dedicated handset, capture failsafes and sovereign control, and even then the one-time-pad core needs honest justification against AES-256 (see Tech item 1), because the certifiers who gate government sales will probe exactly that.

### 4. Sovereign messaging precedents

**France.** On 22 November 2023 the then Prime Minister Élisabeth Borne circulated a directive instructing ministers and their cabinets to stop using WhatsApp, Signal and Telegram and to adopt Olvid from 8 December 2023. Olvid is a French private application, ANSSI-certified, with encrypted metadata. Tchap (created in 2018 by DINUM with ANSSI, the Foreign and Defence ministries, hosted by the Interior Ministry) is the civil-service messenger. DINUM, under the Prime Minister, promotes and deploys Tchap in line with ANSSI standards. The nuance worth carrying into any pitch is that France excluded Signal on sovereignty and control grounds, not because Signal's cryptography is weak.

**Germany.** The Bundeswehr's BwMessenger runs on Matrix and Element, live since November 2020 with more than 100,000 users; BundesMessenger extends the approach to public administration from December 2023. Germany chose an open, self-hostable, federated standard for digital sovereignty rather than Signal.

**Historical UK one-time pad use.** The Foreign Office and Commonwealth Relations Office used one-time tape cipher machines (Rockex and Noreen) and one-time pads for diplomatic and agent traffic from the Second World War into the 1970s; the first Rockex was installed in the Washington embassy in October 1944. The cautionary fact for OTPPhone is that, despite the one-time pad's theoretical perfection, Britain suffered compromises through espionage and through TEMPEST and acoustic emanations (notably at the Moscow embassy). The lesson is precise: one-time pad security collapses at the implementation and physical layer, not in the mathematics, and that is exactly the layer OTPPhone must defend.

### 5. Funding routes

**Y Combinator.** The standard deal is 500,000 US dollars (125,000 on a post-money SAFE for 7 per cent, plus 375,000 on an uncapped SAFE with a most-favoured-nation clause). Roughly 30,000 applications arrive per batch with acceptance around 1.5 to 2 per cent. Founders must relocate to San Francisco for the three-month batch, and YC typically requires a US (Delaware) holding company. The trade-off to weigh: a US flip and SF relocation for a sovereignty-positioned defence product is awkward. It can undercut credibility with European sovereign customers ("why is your sovereign messenger a US company?") and pull the technology under US legal and investment-screening scrutiny. Not disqualifying, but a genuine strategic tension rather than a free option.

**UK non-dilutive and defence routes.** The Defence and Security Accelerator (DASA) funds dual-use and defence innovation without taking equity and provides a route to MOD end-users. From 1 July 2025 DASA was consolidated with other bodies into UK Defence Innovation (UKDI), with around £400 million a year and full operating capability expected by July 2026. NATO DIANA offers accelerator places and grants, with the UK as a host nation and the JANUS consortium delivering UK sites. The National Security Strategic Investment Fund (NSSIF) provides equity into dual-use and national-security startups. Defence tenders are visible through the Defence Sourcing Portal, Crown Commercial Service and NATO's NCIA; realistically a startup wins accelerator or SBRI-style contracts first, then framework subcontracting.

**Defence-prime acquisition as the realistic exit.** Primes (Thales, BAE Systems, Leonardo, RTX/Raytheon, Lockheed Martin) acquire small secure-communications and cryptography firms for their technology and, just as importantly, for their security accreditations and contract vehicles. To be acquirable you generally need a defensible IP position, security accreditation (for example NCSC CAPS or CPA, and NATO approvals) and ideally a foothold on an existing programme. This shapes which certifications to pursue early and argues for building toward accreditation from the start.

### 6. Regulatory risk of the USDT wallet (FCA)

**Current regime.** Since 10 January 2020, businesses carrying on cryptoasset activity in the UK as "cryptoasset exchange providers" or "custodian wallet providers" must register with the FCA under the Money Laundering Regulations for AML and CTF supervision. A custodian wallet provider safeguards or administers cryptoassets or private keys on behalf of customers. A genuinely non-custodial wallet, where keys are held only by the user and the provider never controls them, is generally not a custodian wallet provider and can fall outside the custody limb of MLR registration. However, if the app also lets users exchange (fiat to USDT, or token to token), that exchange function can itself trigger MLR registration as a cryptoasset exchange provider.

**Future regime.** The Financial Services and Markets Act 2000 (Cryptoassets) Regulations 2026 were made on 4 February 2026, with the new FSMA regime expected to come into force on 25 October 2027 and authorisation applications opening around 30 September 2026. Regulated activities will include dealing, arranging, custody, operating a trading platform, stablecoin issuance and staking. The FCA's draft Perimeter Guidance (consultation closing 3 June 2026, final guidance expected around September 2026) reads "arranging" broadly and expressly flags that DeFi and web3 user interfaces and non-custodial wallets face ongoing classification debates and could be captured.

**Net position.** "Non-custodial" defeats the custody limb but is not a blanket exemption, which confirms the checklist's caution. Exposure is lowest if the wallet only stores keys and sends or receives USDT, with no swap, no fiat on-ramp and no order routing. Add any exchange or arranging functionality and FCA registration or authorisation becomes likely. There are also second-order concerns worth weighing: the AML and sanctions reputational surface of a USDT wallet aimed at military and diplomatic users, the offshore status of Tether as issuer, and tightening stablecoin-specific rules. The broader question, which the checklist itself raises, is whether a cryptocurrency wallet belongs in a secure-communications product at all, given how much regulatory surface and threat-model complexity it adds for a benefit that is arguably tangential to the core proposition. Take UK regulatory advice before committing.

---

## Part 2: Tech Feasibility

### 1. Group-chat security model (multi-party one-time pad)

**Fundamentals.** A one-time pad gives perfect (information-theoretic) secrecy only if the key material is truly random, at least as long as the plaintext, used exactly once, and shared secretly in advance. Any reuse of pad material is catastrophic: the XOR of two ciphertexts encrypted under the same pad leaks the XOR of the plaintexts. This is the classic "two-time pad" break that defeated Soviet traffic in the VENONA project.

**Pairwise pads.** Each pair of members shares its own pad, and a group message is encrypted separately to each recipient. Properties: clean compromise isolation (one leaked pad affects one link only) and straightforward revocation (stop using a departing member's pads). Costs: pad provisioning and storage scale with the square of group size; each sender must hold a distinct, never-reused pad segment per recipient; there is no efficient single-ciphertext broadcast; and pad exhaustion accelerates with both group size and traffic.

**Shared group pad.** One pad serves the whole group. The dominant problem is allocation: pad material must be partitioned so that no two senders ever use overlapping ranges, which is a distributed serialisation problem whose failure mode is the two-time-pad disaster. Revocation is the hard part, because a removed member still holds all undelivered pad material, so fresh pad must be redistributed to the remaining members and the old pad discarded. That is expensive and cannot be done purely asynchronously without a trusted coordinator. There is no post-compromise security: a captured pad reveals all future messages encrypted under it until it is replaced.

**Honest comparison.** The modern answer to scalable, asynchronous group key management is Messaging Layer Security (MLS, RFC 9420), which provides forward secrecy and post-compromise security for groups from two to thousands, with efficient key updates. A one-time pad provides neither post-compromise security nor efficient broadcast, and adds severe key logistics. If the promise is "information-theoretic secrecy for groups", it is technically deliverable only with pairwise pads and demanding key logistics, and even then it buys little over an AES-256-based MLS stack against any realistic adversary while losing forward secrecy and post-compromise security.

**What to decide before writing code.** State the exact guarantee. "Information-theoretic confidentiality of message content, assuming perfect pad handling" is true but narrow; it does not cover metadata, endpoint compromise or membership changes. Then decide whether the one-time pad is a genuine security requirement or a marketing position. If it is a requirement, use pairwise pads with strict one-time allocation and hardware-backed pad storage. If it is a position, a vetted AES-256 and MLS stack is far more practical and is what certifiers expect.

### 2. At-rest key model

**Options.** A passphrase-derived key (using a memory-hard KDF such as Argon2id) needs no special hardware and is portable, but it is vulnerable to offline brute force if the device is seized, so its strength rests entirely on passphrase entropy and KDF cost. A hardware-backed key wraps the data-encryption key with a key held in a secure element or StrongBox (Android) or the Secure Enclave (Apple), with hardware rate-limiting on PIN attempts; this is what makes a short PIN safe on a modern phone, but it ties the design to specific hardware.

**Recommended model.** Wrap a passphrase-strengthened data-encryption key with a key-encryption key held in a secure element, so that confidentiality is the logical AND of possessing the device and knowing the secret, with the secure element enforcing attempt limits. This mirrors long-standing military practice, where the crypto ignition key separates the key from the equipment.

**Threat model for a device seized while powered off.** The key state is decisive. In the Before First Unlock state, keys are not resident in RAM and data is encrypted at rest; this is the strong state. After First Unlock, key material is resident and a capable adversary may extract it with exploits or forensic tooling. Design implications: maximise time spent Before First Unlock; use a GrapheneOS-style auto-reboot (default 18 hours, configurable from 10 minutes to 72 hours) to return an idle device to that state automatically; provide a duress credential that triggers an irreversible wipe; and, on hardware that supports it, relock the bootloader with verified boot to prevent a tampered OS from persisting. A device seized powered off and Before First Unlock, on hardware with a secure element and a strong KDF, is the defensible posture. A device seized powered on (After First Unlock) is the dangerous case, which is where the capture failsafes in item 4 matter.

### 3. Metadata privacy

**The named hard problem.** Hiding who talks to whom, when and how often (the social graph) from the server and the network is not addressed by content encryption. It is a research-grade problem.

**Mixnets (Loopix and Nym).** Nym implements the Loopix design: the Sphinx packet format, a layered topology, Poisson mixing delays and cover or loop traffic, in order to break timing and volume correlation. The cost is real: independent testing in 2024 and 2025 notes that the anonymous mode adds enough latency to be unsuitable for real-time voice or video, and cover traffic adds bandwidth overhead. It is well suited to asynchronous messaging and poorly suited to low-latency calls. Nym's roadmap includes a lighter "Outfox" packet format and post-quantum work.

**Closest prior art.** SimpleX hides the social graph by having no user identifiers at all, using pairwise message-queue identifiers so that servers cannot correlate a user's contacts. Cwtch achieves metadata resistance over Tor v3 onion services. Both show that practical social-graph hiding is achievable without a full mixnet, at the cost of some convenience (no global username directory, and reliance on Tor or on queue servers).

**Realistic stance.** Full mixnet-grade metadata privacy with acceptable usability is hard and costly. A SimpleX-style identifier-free design, combined with Tor or queue-server routing, captures most of the practical benefit at lower latency. Promising to hide the social graph requires committing to one of these architectures and accepting its latency and usability cost. It is not free.

### 4. Capture and compromise failsafes

**Military COMSEC practice.** The established pattern is to zeroise (purge all keys in under a second), to separate the key from the device with a crypto ignition key so that a captured device without its key is inert, and to provide emergency zeroize controls and strict key-destruction procedures. The design lessons are to separate key from device, to make destruction instant and irreversible, and to assume capture.

**The EncroChat lesson is cautionary, not a template.** EncroChat offered a panic-PIN local wipe and a network remote wipe. In 2020 French law enforcement compromised it at the server and endpoint level with a malware implant that read messages before encryption and captured lockscreen passwords, and then remotely disabled the wipe feature so that users could not erase their devices even after suspecting compromise. Three takeaways follow. First, endpoint compromise defeats end-to-end encryption entirely, so device integrity (verified boot, locked bootloader, minimal attack surface) is paramount. Second, any centralised control or update channel powerful enough to push a remote wipe is also a single point the adversary will target or turn against users, so a remote-wipe capability is double-edged. Third, prefer local, user-held, autonomous failsafes (duress PIN wipe, auto-reboot to Before First Unlock, dead-man timers) over server-commanded ones, and where remote commands exist, make them cryptographically authenticated and locally overridable.

**Available mechanisms.** GrapheneOS provides a duress PIN or password that triggers an irreversible wipe with no reboot, which cannot be interrupted and also wipes installed eSIMs; an auto-reboot back to the at-rest state; and short auto-lock. To these you can add pad or key zeroisation after a number of failed attempts, and hardware kill switches (as on the PinePhone) to cut the radios. "Frequency changes" in the radio sense do not map onto a cellular handset; the analogue is bearer agility (switching networks or SIMs, falling back to mesh) and disciplined emission control, that is, not transmitting when under threat.

**Gaps to map.** There is no software defence against a powered-on device seized while the user is coerced to unlock it; the mitigations are duress credentials and minimising the time spent After First Unlock. Physical, TEMPEST and supply-chain threats remain, which is the historical Rockex lesson restated.

### 5. Offline and mesh feasibility

**Meshtastic (LoRa).** Open source, with very long radio range (single hop up to roughly 16 km in line of sight, multi-hop mesh quoted at 70 to 150 km), but tiny bandwidth and text only, and it congests with many simultaneous users. It is a useful last-resort text bearer in infrastructure-denied areas, integrated through a companion radio, not a primary channel and not voice-capable.

**Briar (Bluetooth and wifi peer-to-peer).** Short range (Bluetooth on the order of 10 metres, wifi further), no server, syncing offline directly between devices and over Tor when online. Good for contested short-range and censored settings, but text only, small groups, with usability and battery constraints.

**Starlink fallback.** Realistic only with serious caveats. Ukraine's experience shows that terminals can be detected, geolocated and jammed, and that a terminal's radio-frequency emissions can paint a target for fires. It depends on a single commercial US provider, with the attendant availability and political risk, and it needs a dish and power. For non-contested logistics and reach-back it is useful; for front-line, electromagnetically contested or signature-sensitive use it is risky. It is a reach-back bearer, not a covert one, and it is the most detectable of the three.

**Overall.** Mesh and satellite extend reach, but each carries a distinct threat profile. A credible design treats them as fallback bearers with explicit emission-control guidance rather than as always-on features.

### 6. Hardware sourcing

**PinePhone.** Fully flashable, mainline-Linux, with hardware kill switches that cut power to the modem, wifi, Bluetooth, microphone and cameras, and a separate Quectel modem that can be locked or flashed. However, the Allwinner A64 makes a strong locked-down posture difficult, Pine64 deliberately ships without verified boot, and there is no secure element or StrongBox. Verified boot is achievable in principle (an eFuse public-key hash plus a write-protected SPI bootloader) but is do-it-yourself and unproven at production scale. The PinePhone is therefore excellent for ownership, openness and prototyping, and weak as a high-assurance production handset.

**Pixel with GrapheneOS.** The strongest commodity option for a locked-down secure handset: verified boot with a relockable bootloader that supports non-stock keys, a Titan M2 StrongBox secure element, hardware-rate-limited PIN entry, duress PIN, auto-reboot, long security-update support and a minimal attack surface. The downsides are that it is Google hardware, which is a sovereignty and optics question for some government buyers, and that you depend on Pixel availability.

**Cameron's two rooted Nexus handsets.** Suitable as a free platform for software bring-up and iteration only. They are long out of security support and lack a modern secure element, so they must not carry any production use or security claim.

**What can and cannot be locked down.** On Pixels you can relock the bootloader and obtain full verified boot and a secure element. On the PinePhone you get hardware kill switches and complete flashing freedom, but no secure element and only do-it-yourself verified boot. On old Nexus handsets you get neither modern verified boot nor a secure element. The hardware choice therefore trades sovereignty and openness (PinePhone) against assurance (Pixel with GrapheneOS), and that trade-off should be made explicitly against the target customer's accreditation requirements.

---

## Action Items (human, not desk research)

- **Demand validation.** Commission segmented customer-discovery interviews (military, diplomatic, journalistic) through a business or marketing contact before further engineering spend. The three segments have incompatible buying processes and budgets.
- **All-network SIM trial.** Chase Cameron's army-comms contact. Treat the multi-network SIM as a bearer-resilience feature, separate from the cryptographic design.
- **Prototyping hardware.** Use Cameron's two rooted Nexus handsets for software iteration only; plan production on Pixel with GrapheneOS or a hardened board with a secure element.

## Cross-cutting observations

- **Sequence.** The one-time-pad-versus-AES cryptographic decision sits upstream of almost everything else. Resolving it early prevents wasted engineering and shapes the funding and go-to-market choices.
- **The recurring tension.** "One-time pad, unbreakable" is attractive to non-technical buyers, but the technical certifiers who gate government sales will focus on key distribution, key reuse, metadata and endpoint security, which are precisely where a one-time pad gives little or no advantage over a vetted AES-256 and MLS stack. Decide whether the one-time pad is a security requirement or a story, and write the threat model and the exact guarantee down before building.

---

## Sources

**Sovereign messaging and competitors**
- Euronews, France's ministers to adopt Olvid: https://www.euronews.com/next/2023/11/30/frances-government-ministers-to-ditch-using-whatsapp-for-french-app-olvid-over-security-fe
- Olvid, Technology: https://olvid.io/technology/en/ ; Wikipedia, Olvid (software): https://en.wikipedia.org/wiki/Olvid_(software)
- Element, Bundeswehr / BwMessenger case study: https://element.io/en/case-studies/bundeswehr
- SimpleX Chat: https://github.com/simplex-chat/simplex-chat ; https://simplex.chat/
- Cwtch, Open Privacy Research Society: https://openprivacy.ca/work/cwtch/
- Briar, How it works: https://briarproject.org/how-it-works/
- KCL, Protecting secrets: British diplomatic cipher machines 1945-1970: https://kclpure.kcl.ac.uk/ws/files/102323196/Protecting_Secrets_British_diplomatic_EASTER_Accepted30October2018_GREEN_AAM.pdf

**Military comms and mesh**
- Wikipedia, Android Team Awareness Kit: https://en.wikipedia.org/wiki/Android_Team_Awareness_Kit
- UK Defence Journal, Delays continue in Morpheus: https://ukdefencejournal.org.uk/delays-continue-in-morpheus-tactical-comms-programme/
- Meshtastic, Range tests: https://meshtastic.org/docs/overview/range-tests/
- Defense One, Using Starlink Paints a Target on Ukrainian Troops: https://www.defenseone.com/threats/2023/03/using-starlink-paints-target-ukrainian-troops/384361/

**Cryptography and platform security**
- RFC 9420, The Messaging Layer Security (MLS) Protocol: https://www.rfc-editor.org/info/rfc9420/
- Nym, Loopix and mixing documentation: https://nym.com/docs/network/concepts/loopix ; Wikipedia, Nym (mixnet): https://en.wikipedia.org/wiki/Nym_(mixnet)
- GrapheneOS, Features overview: https://grapheneos.org/features
- Wikipedia, EncroChat: https://en.wikipedia.org/wiki/EncroChat
- May Durst, The Endless Conundrum of creating a secure PinePhone: https://daltondur.st/secure_pinephone_1/

**Funding and FCA**
- Y Combinator, The Standard Deal: https://www.ycombinator.com/deal
- DASA: https://www.gov.uk/government/organisations/defence-and-security-accelerator ; NATO DIANA: https://www.diana.nato.int/
- FCA, A new regime for cryptoasset regulation: https://www.fca.org.uk/firms/new-regime-cryptoasset-regulation
- FCA, Cryptoassets: who needs to register (MLRs): https://www.fca.org.uk/firms/cryptoassets-aml-ctf-regime/cryptoassets-who-needs-register
