# ── OTPPhone ProGuard / R8 rules ─────────────────────────────────────────────
# Applied for release builds (isMinifyEnabled = true).
# Debug builds skip this file; the debug APK is never obfuscated.

# ── Kotlin ────────────────────────────────────────────────────────────────────
-keepattributes *Annotation*, InnerClasses, EnclosingMethod, Signature, Exceptions
-keepattributes SourceFile, LineNumberTable   # preserve stack traces

# Kotlin coroutines
-keepnames class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**

# Kotlin serialization (used for WireMessage JSON)
-keepattributes *Annotation*
-keep @kotlinx.serialization.Serializable class * { *; }
-keepclassmembers class * {
    @kotlinx.serialization.SerialName <fields>;
}
-keep class kotlinx.serialization.** { *; }
-dontwarn kotlinx.serialization.**

# ── Hilt / Dagger ─────────────────────────────────────────────────────────────
-keep class dagger.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ActivityComponentManager { *; }
-keep @dagger.hilt.android.AndroidEntryPoint class * { *; }
-keep @dagger.hilt.InstallIn class * { *; }
-keep @javax.inject.Singleton class * { *; }
-dontwarn dagger.**
-dontwarn javax.inject.**

# ── Room ──────────────────────────────────────────────────────────────────────
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao interface * { *; }
-keepclassmembers class * extends androidx.room.RoomDatabase {
    abstract ** *Dao();
}
-dontwarn androidx.room.**

# ── OkHttp / WebSocket ────────────────────────────────────────────────────────
-keepnames class okhttp3.internal.** { *; }
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**

# ── Tink (HPKE + X25519) ─────────────────────────────────────────────────────
# Tink uses reflection to load primitive implementations by class name.
-keep class com.google.crypto.tink.** { *; }
-keepclassmembers class com.google.crypto.tink.** { *; }
-dontwarn com.google.crypto.tink.**

# ── Nearby Connections (Bluetooth key exchange) ───────────────────────────────
-keep class com.google.android.gms.nearby.** { *; }
-keep class com.google.android.gms.common.** { *; }
-dontwarn com.google.android.gms.**

# ── AndroidX / Compose ───────────────────────────────────────────────────────
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**
-keep class androidx.lifecycle.** { *; }
-dontwarn androidx.lifecycle.**
-keep class androidx.navigation.** { *; }
-dontwarn androidx.navigation.**

# ── DataStore ────────────────────────────────────────────────────────────────
-keep class androidx.datastore.** { *; }
-dontwarn androidx.datastore.**

# ── App-specific: keep all model / entity classes unobfuscated ────────────────
# Prevents Hilt and Room from failing to find injected types at runtime.
-keep class com.otpphone.** { *; }

# ── Miscellaneous ─────────────────────────────────────────────────────────────
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
