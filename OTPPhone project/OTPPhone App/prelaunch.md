# OTPPhone — Pre-Launch Checklist

A launch gate, not a wishlist. Work top-down: the **🔴 Blockers** must all be checked
before any public release; **🟠 High** before the first *stable* release (i.e. before you
ever ship a v1.x update); the rest is hardening, review, and paperwork that a crypto
messenger warrants.

**Assumed distribution model:** self-distribution of a signed release APK via
`download.rhydianwilliams.com` (Cloudflare R2 + Worker). The Google Play–only items are
isolated in the last section — ignore them unless Play is also in scope.

> Effort/risk notes are inline so you can triage without re-deriving the tradeoffs.
> Last updated: 2026-06-07.

---

## ✅ Recently completed

- [x] **Launch-copy & capture polish (2026-06-07).** `FLAG_SECURE` is now skipped in **debug**
  builds only (release stays secure) so store screenshots + the demo video can be captured;
  added a **no-warranty disclaimer** and a **background-delivery (~6 h/day) limit note** to
  Settings → About; fixed the stale version label (now reads `BuildConfig.VERSION_NAME`);
  scanned all UI copy for security overclaims (clean). Relay region (`London (lhr)`) filled into
  the privacy policy.
- [x] **Release signing wired in + keystore generated (2026-06-07).** `app/build.gradle.kts` has a
  `signingConfigs.release` loaded from `keystore.properties` (or `OTPPHONE_KEYSTORE_*` env vars for
  CI), attached to the `release` build type. The upload keystore exists (`otpphone-release.jks`,
  alias `otpphone`, RSA-4096, valid to 2053) and `gradlew :app:signingReport` confirms the release
  variant signs with it (SHA-256 `60:C0:DA:79:…:87:EA`). `.gitignore` excludes the keystore +
  properties. A signed release AAB has been built (`app-release.aab`, 30.8 MB, R8 clean). *Still
  pending (needs you): verify it on a device; back up the `.jks` + password offline.*
- [x] **Room migration safety (2026-06-07).** `exportSchema = true` with the baseline committed
  (`app/schemas/com.otpphone.storage.AppDatabase/4.json`); `fallbackToDestructiveMigration()`
  removed and replaced with an `AppDatabaseMigrations` registry; the open-with-recovery path now
  re-throws Room migration/integrity errors instead of silently wiping (it still wipes only a
  genuinely undecryptable/corrupt file). A future schema bump without a migration now fails loudly.
- [x] **First-run onboarding (2026-06-07).** New `OnboardingScreen` explains E2E encryption, the
  in-person Bluetooth pad exchange, and the single-device/no-backup model — with a **required
  acknowledgement** of "no backups" before "Get started" enables. Persisted via
  `SettingsStore.onboardingComplete`, gated in `MainActivity`.
- [x] **16 KB page-size alignment.** Migrated the deprecated
  `net.zetetic:android-database-sqlcipher:4.5.4` (4 KB-aligned `libsqlcipher.so`) to the
  maintained `net.zetetic:sqlcipher-android:4.9.0`. Verified all native libs in the built
  APK are now 16 KB-aligned. Held at 4.9.x on purpose — 4.10+ needs `androidx.sqlite:2.6+`
  which would force a Room 2.7+ upgrade.

---

## 🔴 Blockers — do not launch without these

- [ ] **Ship a signed *release* build instead of the debug APK.** *(critical)* The
  `signingConfigs.release` wiring now exists, but no keystore has been generated and no signed
  artifact has been produced/distributed yet — the download page still serves the **debug**
  (`debuggable=true`) APK. For a security app a debuggable build is fatal: anyone with the device
  can attach a JDWP debugger and read decrypted pads/plaintext out of the running process,
  bypassing the entire Keystore + SQLCipher model.
  - [x] Add `signingConfigs.release` wired into the `release` build type, loading secrets from
        `keystore.properties` / env vars (never commit the keystore or passwords). *Done — see
        `app/build.gradle.kts` + `keystore.properties.example`.*
  - [x] Generate a release keystore; store it + passwords somewhere durable and backed up. *Done —
        `otpphone-release.jks` generated + wired (verified via `signingReport`). With **Play App
        Signing** this is the *upload* key (recoverable via Play support); for the self-distributed
        APK, losing it = you can never sign an update for the same app identity. **Back it up offline.***
  - [x] Build the signed artifact: `./gradlew :app:bundleRelease` produces a **signed**
        `app/build/outputs/bundle/release/app-release.aab` (30.8 MB); R8/minify + resource
        shrinking run clean. *Confirming it actually runs is the next two blockers (on-device).*
- [ ] **Verify the SQLCipher path works in the *release* (R8/minified) build on a real device.**
  *(low effort, critical)* The 16 KB migration changed the DB factory; minification is
  where keep-rule gaps surface. The release AAB now builds with **R8 + resource shrinking and no
  keep-rule build failures** (good sign the consumer ProGuard rules are complete) — but still
  confirm at **runtime** that the encrypted DB actually opens in the release artifact, not just debug.
- [ ] **Full end-to-end run of the release build on two physical phones.** *(medium effort)*
  Pad exchange over Bluetooth → OTP message → erase-after-use → destroy vault → background
  delivery → app-lock. There are **no instrumented/DB/UI tests**, so this integrated path
  has only ever been hand-validated — do it against the release artifact.
- [ ] **Upgrade/data-survival test.** *(low effort)* Install the previously distributed
  build, then install this release over the top, and confirm an existing encrypted DB still
  opens after the SQLCipher artifact change (no crash, no silent wipe).

---

## 🟠 High priority — data-loss landmines before a stable release

- [x] **Replace `fallbackToDestructiveMigration()` with real Room migrations.**
  *(done 2026-06-07)* In `app/.../storage/AppDatabase.kt`: destructive fallback removed,
  `exportSchema = true` with the v4 baseline committed under `app/schemas/`, an
  `AppDatabaseMigrations` registry added, and the open-with-recovery path hardened to re-throw
  Room migration/integrity errors (so a future schema bump with no migration fails loudly
  instead of silently wiping history + contacts). No historical migrations were needed (no
  schema before 4 was ever released).
  - [ ] Add a Room migration test (`MigrationTestHelper`, `app/src/androidTest`) **once the
        first real migration exists** — needs an emulator/device to run, so it's deferred until
        there's a migration to test.
- [x] **Decide the backup / device-migration story.** *(decided)* A lost/replaced phone = all
  history + identity gone (non-extractable keys + `allowBackup=false`).
  - [ ] ~~Implement the designed encrypted, passphrase-protected export~~ — **decided against.**
        No backups: data lives on that device and only that device.
  - [x] Make the "data lives on exactly one device, back up nothing" model explicit in onboarding
        so it's a conscious user choice, not a surprise. *Done — the first-run `OnboardingScreen`
        requires the user to acknowledge "no backups" before continuing.*

---

## 🟡 Reliability & operations

- [x] **Set expectations** for background-delivery limits *(done 2026-06-07)*. `MessagingService`
  uses `foregroundServiceType="dataSync"`, which has a ~6 h/day budget on Android 14/15 (target
  SDK 35); messages stop arriving when backgrounded past that. The limit is now communicated in
  **Settings → About**. *(The proper fix — FCM push, server work — remains a future option, not
  required for v1.)*
- [ ] **Relay uptime monitoring + alerting.** *(medium effort)* The Fly relay is
  single-instance, in-memory, no HA by design — a deploy or crash drops every live
  connection and all queued offline messages. Add health-check monitoring + alerts and a
  low-downtime deploy approach.
- [x] **Reviewed relay metadata logging** *(2026-06-07)*. Finding: `Server.kt` logs only
  connection/routing events keyed by the public `userId` (connect/disconnect, routed, rate-limit)
  to **stdout** via a ConsoleAppender — **no IP addresses are logged and nothing is persisted** (no
  file/DB appender). Retention is therefore only whatever Fly.io keeps stdout for (transient). The
  privacy policy reflects this. Optional future lever: confirm/limit Fly log retention or a drain.
---

## 🔵 Security review & legal

- [ ] **Independent security review of the crypto + key exchange.** *(external, high value)*
  Focus: SAS/PIN binding in the Bluetooth exchange, keystream offset-reuse guarantees, HPKE
  associated-data binding, Keystore/StrongBox failure modes, and the relay auth handshake.
  (`crypto/`, `bluetooth/`, `server/Server.kt`.)
- [ ] **Privacy policy** — *finalised, pending hosting*. Complete at
  `distribution/privacy-policy.md` (source) + `distribution/privacy-policy.html` (ready-to-host),
  all values filled (Vernam Technologies · UK · contact@vernamtechnologies.com · relay region
  London/lhr) and the logging section corrected to match the actual relay (stdout only, no IP
  logging, no persistence — see 🟡 below). Remaining: host it at
  `https://vernamtechnologies.com/privacy` and ideally a quick legal review.
- [ ] **Encryption export-compliance check.** *(external)* Strong crypto carries
  notification/registration obligations in some jurisdictions (e.g. US EAR) even for
  mass-market/self-distributed apps; some countries restrict use. Get a real check — not
  legal advice.
- [x] **No-warranty / liability disclaimer** *(done 2026-06-07)*. A clear "provided as is, no
  warranty, no software is perfectly secure" disclaimer is surfaced in **Settings → About**.
- [x] **Truthful security claims everywhere** *(verified 2026-06-07)*. Scanned all user-facing
  copy — no overclaims (no "unbreakable", "military-grade", etc.). Onboarding + About state the
  honest "computationally secure, ≈ a strong stream cipher — not a literally unbreakable pad"
  framing, aligned with ARCHITECTURE §9.

---

## ✨ Polish

- [x] **App icon / branding.** Confirm `@mipmap/ic_launcher` is a real icon, not the default. - DONE
- [x] **Onboarding / first-run** clearly explains the in-person pad exchange and the
  single-device data model. - DONE (`OnboardingScreen.kt`: E2E + Bluetooth pad exchange +
  required no-backup acknowledgement).
---

## 🟣 Google Play delta (only if Play is also a channel)

> Listing copy + pre-filled answers for everything below are in
> `distribution/google-play-submission.md`. Shared `{{PLACEHOLDER}}`s live in the privacy-policy files.

- [ ] Register a **Play Console developer account** ($25 one-time + identity verification).
- [x] Build an **AAB**, not an APK. *Done — signed `app/build/outputs/bundle/release/app-release.aab`
      (30.8 MB), R8 clean. Rebuild any time with `./gradlew :app:bundleRelease`.*
- [ ] Enroll in **Play App Signing** (upload key = your release key; Google holds the signing key).
- [ ] Host the **privacy policy at a public URL** (required by Play) — *finalised* at
      `distribution/privacy-policy.html`; just host it at `https://vernamtechnologies.com/privacy`.
- [ ] Complete the **Data Safety** form — *draft answers ready (recommend "no data collected",
      with a documented fallback).* 
- [ ] Set a **content rating** (IARC) — *draft answers ready.*
- [ ] Justify the **`dataSync` foreground service** (declaration + demo video) — *declaration text
      drafted; demo video still to record.*
- [ ] Add the **location-permission declaration** (fine/coarse location for the Nearby BT scan) —
      *justification drafted.* (New: Play wants this in addition to the `dataSync` declaration.)
- [ ] Answer the **export-compliance** question — *draft + caveat ready; still needs a real check
      (custom crypto may require a BIS self-classification report).*
- [ ] Produce **store assets**: 512 icon, 1024×500 feature graphic, 2–8 phone screenshots.
      `FLAG_SECURE` blanks captures — now skipped in **debug** builds only, so just capture from a
      `debug` build (the release AAB stays secure). The demo video can be captured the same way.
- [x] `targetSdk 35` already satisfies the current API-level requirement. ✓
- [ ] Budget for a **slow review** on a messaging/crypto app.

---

## 🚦 Launch gate

**Do not publish until every 🔴 Blocker is checked.** Recommended order:
signed release build → release-artifact verification → two-device E2E → upgrade test →
then work the 🟠 items before the first update ships.
