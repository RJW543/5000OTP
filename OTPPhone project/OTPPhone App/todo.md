# OTPPhone — Feature & Improvement Backlog

Candidate features and improvements, grouped by how well they fit the app's
"serious security tool" ethos. Edit freely — delete anything you don't want,
check off anything you do.

> Each item notes effort/risk and any architectural caveat so you can triage
> without re-deriving the tradeoffs.

---

## Done — implemented

- [x] **Camera TRNG for OTP pad generation.** Camera2 capture (RAW if supported, else YUV luma)
  → frame-difference + LSB de-correlation → NIST 800-90B-style min-entropy estimate + RCT/APT
  health tests → **information-theoretic Toeplitz-hash extractor** sized to the measured entropy
  (not SHA-256 whitening). Two entry points: the **Labs benchmark** (Settings → Labs, measures +
  discards) and **live pad generation** via `PadEntropyProvider`, wired into
  `BluetoothKeyExchange.sendPad()`. Gated by a Settings toggle ("Camera-entropy OTP pads",
  default on) and **auto-falls back to SecureRandom** if the camera is unavailable / permission
  denied / entropy fails health checks — so it only ever upgrades, never breaks. The key-exchange
  "complete" screen shows which source was used. Verified on-device: RAW_SENSOR, ~329 KB/s,
  0.999 b/bit min-entropy, RCT/APT pass, output χ²≈255. **Scope: OTP pads only** — HPKE, the DB
  passphrase, and the relay nonce still use SecureRandom by design.
- [x] **Pad budget UX.** Proactive amber "OTP pad running low · N% left" banner before
  exhaustion (triggers at ≤20% of your send half), with a lifetime-average **~N days left at
  this rate** estimate and bytes remaining. The status pill goes amber + shows the percentage
  when low; the banner is tappable (→ key exchange) and dismissible. Derived entirely from the
  existing `OTPSession` (`consumedBytes` since `createdAtMs`) — no new storage. Threshold is
  one constant (`PadBudget.LOW_FRACTION`).
- [x] **Disappearing messages.** Per-conversation self-destruct timer (Off / 30s / 5m / 1h /
  1d), set from the chat's ⋮ menu and synced to the peer via a `timer` control frame. Each
  message carries an absolute `expiresAtMs`; expired rows are swept from the SQLCipher store
  every 60s app-wide and every 5s in the open chat. Bubbles show a small timer icon.
- [x] **Reply / quote, reactions, edit / unsend.** Long-press a bubble for a tapback-style
  emoji row + actions. Reply quotes the original (only the **id** crosses the wire — the
  preview is resolved from the local store, never leaking plaintext to the relay). Reactions
  toggle and sync; edit re-encrypts in place and shows an "edited" tag; "delete for everyone"
  scrubs the content on both devices and leaves a tombstone. Edits/reactions/unsend ride new
  `edit`/`reaction`/`unsend` control frames.
- [x] **Background delivery + notifications.** A foreground `MessagingService` holds the
  relay WebSocket so messages arrive while the app is closed, and posts a notification per
  inbound message. Content is hidden by default ("New message"); a Settings toggle opts
  into sender + text previews. Notifications are suppressed while the app is foregrounded
  and tapping one deep-links into the chat. *Caveat:* `dataSync` foreground services have a
  ~6h/day budget on Android 14+ — FCM remains the "proper" long-term push path (needs
  server work).
- [x] **App lock.** Biometric / device-credential lock via `BiometricPrompt` (delegates to
  the device's own fingerprint/face/PIN — no secret stored by the app). Toggle + auto-lock
  timeout (Immediately / 1 min / 5 min) in Settings. Locked content isn't composed at all,
  and the lock state is decided synchronously at startup so nothing flashes before locking.
- [x] **Delivery & read receipts.** End-to-end via the `WireMessage` JSON protocol (the
  orphaned `DeliveryReceipt` proto had no build plugin, so it was dead code). Outbound
  bubbles now show ticks: clock (queued) → single check (sent) → double check (delivered)
  → green double check (read). Status is monotonic (a late receipt can't move it backward)
  and read receipts are gated by a Settings toggle.
- [x] **Contacts page.** New address-book tab listing every contact whether or not a thread
  exists; the Chats tab now shows active threads only. Tap a contact to open/start a chat.
- [x] **Settings screen.** New tab hosting My User ID (QR + safety words), the read-receipts
  toggle, app-lock controls, notification-preview toggle, and an About/crypto section.
- [x] **Bottom navigation.** Chats · Contacts · Settings, matching the terminal aesthetic.

## Context: gaps noticed while reading the code

- **`userId = hash(pubkey)`** — identity is self-certifying; key-substitution MITM is
  already defeated (`WebSocketMessagingService.kt:376`). Strong foundation.

---

## Tier 1 — Reliability gaps to close first

- [ ] **Backup & device migration.** Today `allowBackup="false"` + non-exportable Keystore
  keys means a lost phone = everything gone. Add an encrypted, passphrase-protected
  export of history + identity key (explicitly **not** OTP pads).

## Tier 2 — Messaging features that fit naturally

- [ ] **Attachments (images / files / voice notes).** Big usability win. **Caveat:** media
  must be HPKE-only, *not* OTP — a single 2 MB photo would instantly exhaust a pad
  measured in KB. Reserve the one-time-pad for text; label media honestly in the badge.

## Tier 3 — Security features that are real differentiators

- [ ] **Duress PIN / panic wipe.** A fake unlock code that silently zeroes vaults +
  history. Perfectly aligned with the threat model.
- [ ] **Hidden / decoy conversations** (plausible deniability).
- [ ] **Key-change alerts & re-verify.** `SafetyPhrase` already exists — proactively warn
  "X's safety words changed" if a pinned key ever rotates.
- [ ] **Alternative pad transfer.** NFC tap or QR-sequence as fallbacks to Bluetooth for
  the in-person exchange.

## Specific ideas requested

- [ ] **Group chats.** *Doable, scope carefully.* OTP pads are pairwise + physically
  exchanged, and the wire format is 1:1 today. Realistic design: **groups are
  HPKE-only** (sender-keys / fan-out), OTP stays a 1:1 feature. Badge groups honestly
  as "HPKE" so the security claim stays truthful.
- [ ] **USDT / built-in wallet.** *Not recommended as built — high risk, low fit.*
  Turns a messaging app into a custody target; USDT is centralized + chain-bound and its
  RPC calls leak transaction metadata that undercuts the privacy posture; plus money-
  transmission / KYC / Play Store exposure. If payments matter, go **non-custodial and
  delegated** — carry a payment request/address in chat and hand signing to the user's
  external wallet (WalletConnect / deep link). Treat even that as a later, optional module.

---

## Suggested first picks

Background delivery, app lock, receipts, contacts, settings, disappearing messages, and the
reply/react/edit/unsend set are all done now. The next high-value items are **backup /
device migration** (closes the "lost phone = everything gone" hole) and **attachments**
(the biggest remaining usability gap — HPKE-only per the caveat above). Hold groups until
the HPKE-only model is decided; shelve the wallet unless there's specific user pull.
