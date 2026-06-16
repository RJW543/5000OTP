# Non-Custodial TON / USDT Wallet — Implementation Design

> **Status:** design notes only. No code has been written yet. This captures the analysis of
> how a non-custodial TON-based USDT wallet *could* be implemented in OTPPhone, grounded in the
> existing codebase, before committing to a build.

---

## Verdict

Non-custodial + **delegated** (the user signs locally; we never hold keys or funds) is the right
approach — it's the only version of an in-app wallet that doesn't fight the app's privacy/security
posture. The proposed flow (local key-gen → encrypted local storage → public API for balance →
local signing + broadcast) is essentially correct. The sections below fill in the parts that
actually decide whether it's *safe*.

---

## Correction up front: "seed phrase" vs "Secure Enclave" are in tension

A design can't both (a) give the user a recoverable **24-word seed phrase** and (b) keep the key
**hardware-bound / non-exportable**:

- A 24-word phrase the user can write down **is, by definition, exportable** key material. If it
  can leave the device in human-readable form, it isn't hardware-bound.
- TON signs with **Ed25519**. The **iOS Secure Enclave can't store Ed25519 at all** (P-256 only),
  and Android Keystore only added Ed25519 at API 33 — and even then you can't import a
  seed-derived key and keep a recoverable phrase.

**What real TON wallets actually do (and what we'd do):** the mnemonic is **AES-encrypted with a
Keystore-held key (StrongBox→TEE) and stored in app-private storage**, decrypted into RAM only at
signing time, gated by biometric. That's *encrypted-at-rest + biometric* — **not** "the key never
leaves the secure element." The UI must say so honestly.

> This app is Android-only, so Secure Enclave (iOS) is moot — **Android Keystore** is the target.
> The codebase already implements this exact wrap pattern in `DatabasePassphraseManager` and
> `OTPGenerator.provisionKeyIfAbsent()` (StrongBox→TEE AES-GCM). The wallet seal is a near-copy.

---

## TON specifics that make or break it

- **USDT on TON is a Jetton (TEP-74), not a native balance.** Each user has a separate
  **jetton-wallet contract** holding their USDT. "Check balance" queries the jetton wallet;
  "send" constructs a **jetton-transfer body** (op `0x0f8a7ea5`) that your main wallet sends to
  *your* jetton wallet, which forwards to the recipient's. It is not a plain transfer.
- **You need native TON (gas) to move USDT** — ~0.05–0.1 TON per jetton transfer. A user with
  $10 USDT and 0 TON **cannot send**. Must handle "insufficient gas" explicitly, or adopt a
  **W5 wallet + gasless relayer** (relayer fronts the TON, takes a few cents of USDT). This is
  the single biggest UX wrinkle.
- **Address derivation:** Ed25519 keypair → wallet contract (**v4R2** is the safe baseline; **W5**
  enables gasless) → address is deterministic from code+pubkey; the contract auto-deploys on first
  send. **USDT has 6 decimals, TON has 9 (nanoton)** — get units right.
- **Library:** `org.ton:ton-kotlin` (Kotlin Multiplatform) provides mnemonic↔key, wallet
  contracts, Cell/TLB to build the jetton body, and a **lite-client** to talk to TON liteservers
  directly instead of a single HTTP API company (see Privacy below).

---

## What the app already provides for free

| Need | Reuse |
|---|---|
| Seal the seed (StrongBox→TEE AES-GCM) | `DatabasePassphraseManager` / `OTPGenerator` pattern |
| Gate signing / reveal-seed behind biometric | `BiometricAuth` (lock package) |
| Keep the seed screen out of screenshots | `FLAG_SECURE` (already global) |
| Address QR + scan-to-add | existing `zxing` + `MyIdDialog` patterns |
| A place to put it | bottom nav (add a Wallet tab) or Settings → Labs first |
| In-chat payment, end-to-end | the existing encrypt/decrypt message pipeline |
| Zero secrets after use | the existing `fill(0)` / `zeroize` discipline |

---

## Standout integration: payment requests *inside* the ciphertext

The piece that fits this app and nothing else does. Don't bolt a wallet on the side — **encode a
payment request as a structured body inside the existing E2E-encrypted message**:

```json
{ "otpphone_payment": { "to": "<addr>", "amount": "10.00", "token": "USDT", "memo": "..." } }
```

Because it rides inside the HPKE/OTP ciphertext, **the relay never sees it** — same guarantees as
any message, no new plaintext wire fields. The recipient's `ChatScreen` detects the structured
body and renders a "Request: 10 USDT — [Pay]" card instead of plain text; tapping pre-fills the
send sheet. Fully delegated (the recipient consciously signs from their own wallet). It slots in
right next to the reply/reaction/edit message handling that already exists.

---

## Threat-model tensions to decide on (the crux for a privacy app)

1. **Balance/broadcast queries leak your wallet address + IP + timing** to whoever you query. For
   an app built around an untrusted relay and metadata minimization, bolting on a single API
   company (e.g. TonAPI) that then sees all your addresses and activity is a real regression.
   Mitigations, by effort: query **public liteservers via ton-kotlin's lite-client** (no single
   API company, but the node still sees your IP) → route over **Tor/proxy** → run your **own
   node**. At minimum: **opt-in and disclosed**.
2. **A wallet address in a chat permanently links your messaging identity to a public, immutable
   ledger.** If you and a contact are ever doxxed, every payment between you is forever visible.
   **Keep the wallet identity completely separate from the messaging identity** — do **not**
   derive the TON key from the `userId` keypair, and don't auto-attach an address to your profile.
3. **Expanded attack surface.** A messenger that holds a seed and signs transactions becomes a
   fund-draining target; the seed is in RAM during signing. Inherent — biometric-gate every
   signing op, zero the seed immediately after use, keep the wallet code small and auditable.
4. **Play Store / regulatory.** Non-custodial is far more acceptable than custodial, but
   financial-app policies still apply. Check before shipping; out of scope to resolve here.

---

## Proposed shape (`com.otpphone.wallet`)

- `WalletKeyStore` — generate / seal / unseal the 24-word mnemonic (Keystore-AES, biometric-gated).
  Modeled on `DatabasePassphraseManager`.
- `TonClient` (interface) — `balance()`, `seqno()`, `jettonWalletAddress()`, `sendBoc()`.
  Implementation over lite-client (more private) or TonAPI (simpler); mockable for tests.
- `WalletRepository` + `WalletViewModel` — balance state, send flow, tx status.
- UI: `WalletScreen` (balance, Receive = address + QR, Send = addr/amount → biometric → sign →
  broadcast), `RevealSeedScreen` (explicit warnings, FLAG_SECURE).
- Chat: payment-request card renderer + a "Request / Send" affordance in `ChatScreen`.

---

## Phasing

1. **Read-only:** generate + seal wallet, show address / QR, **display USDT balance**. No signing —
   proves key management + API/privacy posture with zero fund risk.
2. **Send to an address** — biometric-gated signing, gas checks, jetton-transfer body.
3. **In-chat payment requests** — the ciphertext-embedded card.
4. **Gasless (W5 + relayer)** — so users without TON can still pay.

> Recommended start: **Phase 1, read-only, over the lite-client.** It de-risks key management and
> the privacy story before any money can move.

---

## Open decisions (shape everything)

- **Data layer:** lite-client (privacy) vs TonAPI HTTP (simplicity)?
- **v1 scope:** read-only (balance/receive) vs straight to sending?
- **Wallet contract:** v4R2 (simple) vs W5 (enables gasless, more moving parts)?
- **Backup model:** confirm the 24-word reveal (exportable, encrypted-at-rest) — and accept that
  "non-exportable hardware-bound" is *not* what that gives you.
- **Identity separation:** confirm the TON key is independent of the messaging `userId` key.
