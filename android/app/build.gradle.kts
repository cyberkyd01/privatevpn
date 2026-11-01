import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Version: -PappVersion=1.2.3 (a leading "v" from a git tag is accepted).
// versionCode = MAJOR*10000 + MINOR*100 + PATCH (ARCHITECTURE §15.4).
val appVersion: String = providers.gradleProperty("appVersion").orNull
    ?.trim()?.removePrefix("v")?.takeIf { it.isNotEmpty() } ?: "1.0.0"
val appVersionCode: Int = run {
    val m = Regex("""^(\d{1,3})\.(\d{1,2})\.(\d{1,2})$""").matchEntire(appVersion)
        ?: throw GradleException("appVersion must be MAJOR.MINOR.PATCH (MINOR, PATCH < 100), got '$appVersion'")
    val (major, minor, patch) = m.destructured
    val code = major.toInt() * 10000 + minor.toInt() * 100 + patch.toInt()
    if (code < 1) throw GradleException("appVersion must be at least 0.0.1")
    code
}

// Release signing only when the CI (or the developer) provides a keystore.
val keystorePath: String? = providers.environmentVariable("ANDROID_KEYSTORE_FILE").orNull?.takeIf { it.isNotBlank() }

// The Go core, produced by `make core-aar` (gomobile bind); git-ignored.
val coreAar = file("libs/core.aar")

android {
    namespace = "app.privatevpnpro"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.privatevpnpro"
        minSdk = 26
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersion
    }

    signingConfigs {
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = providers.environmentVariable("ANDROID_KEYSTORE_PASSWORD").orNull
                keyAlias = providers.environmentVariable("ANDROID_KEY_ALIAS").orNull
                keyPassword = providers.environmentVariable("ANDROID_KEY_PASSWORD").orNull
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keystorePath != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/*.version", "DebugProbesKt.bin")
        }
    }

    lint {
        // Lint must not depend on network lookups for newer library versions.
        checkDependencies = false
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion")
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(files("libs/core.aar"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)

    implementation(libs.zxing.android.embedded)
}

// Fail early with a useful message instead of a wall of "unresolved
// reference: mobile" errors.
val checkCoreAar by tasks.registering {
    val aar = coreAar
    doLast {
        if (!aar.isFile) {
            throw GradleException("android/app/libs/core.aar is missing — build it first with `make core-aar` (gomobile bind ./mobile)")
        }
    }
}
tasks.named("preBuild") { dependsOn(checkCoreAar) }
