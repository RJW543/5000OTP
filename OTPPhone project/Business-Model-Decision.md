# OTPPhone — Business Model Decision

**Decided:** 6 June 2026
**Status:** Direction agreed. Several upstream questions remain open (see below).

## Decision

OTPPhone will run on a two-tier model.

**1. Public tier — free, software-only.**
The existing Android app is released as a free, publicly available product. No hardware lock; it runs on standard Android through the current APK distribution. The purpose of this tier is reach, credibility and a distribution funnel, not direct revenue.

**2. Organisational tier — paid, self-hosted on dedicated hardware.**
A paid service for institutions. Rhydian supplies the dedicated hardware, and the service allows the organisation to self-host the relay and run the deployment under its own control. This mirrors the sovereign precedents of BwMessenger (Germany) and Tchap (France), where institutions self-host rather than rely on a third-party server.

## Rationale

Hardware lock-in only earns its keep where there is budget, an accreditation requirement and a threat model that justifies carrying a second device. That describes organisations, not the general public. Forcing the public onto dedicated hardware would destroy the network effect, since people would have nobody to message, and would discard the one consumer group (journalists and NGOs) that is valuable as free credibility rather than as a revenue line.

It also avoids the EncroChat posture. Selling secure handsets to the general public, marketed on unbreakability, with a relay the vendor operates, is the same shape as EncroChat, Sky ECC and Phantom Secure, all of which were dismantled and whose operators were prosecuted. Accountable institutional buyers are a safer place to stand, both legally and reputationally.

## Open questions (upstream of execution)

These are not yet decided and should not be assumed away:

1. **Organisational hardware choice.** Do not default to the PinePhone. It has no secure element, no StrongBox and ships without verified boot, so it would break the Android Keystore based pad-at-rest model the app already depends on, and would require an Android-to-Linux rewrite or an unreliable compatibility layer. A Pixel-with-GrapheneOS class device with a secure element and relockable verified boot preserves the existing security model and is the stronger candidate.

2. **Relay productionisation.** The relay is currently single-instance and in-memory by design. Self-hosting cannot be sold credibly to an organisation until the relay can run with shared state for high availability. This is now on the critical path for the paid tier.

3. **One-time pad versus AES positioning.** Still unresolved, and the research places this decision ahead of further engineering and go-to-market commitment.

4. **Demand validation.** Segmented customer-discovery interviews (military, diplomatic, journalistic) have not yet been run. The research treats this as a prerequisite to further spend.
