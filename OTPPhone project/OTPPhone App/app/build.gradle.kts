import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

// Release signing secrets. Loaded from keystore.properties (preferred — gitignored, see
// keystore.properties.example) or, for CI, from environment variables. Absent in a fresh
// clone → the release build still configures, it just stays unsigned until secrets exist.
// The keystore + passwords must NEVER be committed.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) FileInputStream(keystorePropertiesFile).use { load(it) }
}
fun signingSecret(propKey: String, envKey: String): String? =
    keystoreProperties.getProperty(propKey) ?: System.getenv(envKey)

val releaseStorePath = signingSecret("storeFile", "OTPPHONE_KEYSTORE_FILE")
// Resolve relative to the repo root (where keystore.properties lives), not the app module,
// so a relative storeFile is unambiguous. Absolute paths are returned as-is.
val hasReleaseSigning = releaseStorePath != null && rootProject.file(releaseStorePath).exists()

android {
    namespace = "com.otpphone"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.otpphone"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        // Default (release): production relay over TLS. wss:// IS the scheme — no extra https://.
        buildConfigField("String", "SERVER_URL", "\"wss://otpphone-relay.fly.dev/ws\"")
    }

    signingConfigs {
        // Created only when secrets are present, so `assembleDebug` and a secret-less CI
        // checkout still configure. With Play App Signing this is your *upload* key.
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(releaseStorePath!!)
                storePassword = signingSecret("storePassword", "OTPPHONE_KEYSTORE_PASSWORD")
                keyAlias = signingSecret("keyAlias", "OTPPHONE_KEY_ALIAS")
                keyPassword = signingSecret("keyPassword", "OTPPHONE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Sign with the release key when it's available; otherwise the artifact is left
            // unsigned (build still succeeds) rather than silently falling back to the debug key.
            if (hasReleaseSigning) signingConfig = signingConfigs.getByName("release")
        }
        debug {
            // Point the debug build at the hosted Fly relay so a sideloaded debug APK works
            // on a real phone (the emulator alias 10.0.2.2 is unreachable from a physical device).
            // For local testing (emulator + `./gradlew :server:run`), switch this to "ws://10.0.2.2:8080/ws".
            buildConfigField("String", "SERVER_URL", "\"wss://otpphone-relay.fly.dev/ws\"")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }  // migrate to compilerOptions when AGP stabilises

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

// Export the Room schema to app/schemas so migrations can be written and tested against a
// committed baseline (paired with exportSchema = true on @Database). Commit the generated JSON.
ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.navigation.compose)
    debugImplementation(libs.androidx.ui.tooling)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.hilt.navigation.compose)

    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)

    implementation(libs.tink.android)

    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)

    implementation(libs.nearby.connections)

    implementation(libs.coroutines.android)
    implementation(libs.datastore.preferences)
    implementation(libs.security.crypto)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)

    // QR: generate (My ID) + scan (Add contact)
    implementation(libs.zxing.embedded)

    // SQLCipher — AES-256 encryption of the Room database at rest
    implementation(libs.sqlcipher.android)
    implementation(libs.androidx.sqlite)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
}
