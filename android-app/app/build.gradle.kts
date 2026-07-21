import java.io.File

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.example.dzta"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.dzta"
        minSdk = 34
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    // Do NOT compress or strip the pVM payload binary
    aaptOptions {
        noCompress("dzta-protected-prover")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.1"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.material3)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}

// ==============================================================================
// RUST PVM AUTOMATION TASKS
// ==============================================================================

tasks.register<Exec>("buildRustProver") {
    workingDir = File(projectDir, "../../") // Points to dzta-workspace root
    commandLine(
        "cargo", "build",
        "--target", "aarch64-unknown-linux-musl",
        "--package", "dzta-protected-prover",
        "--release"
    )
}

tasks.register<Copy>("copyRustProverAsset") {
    dependsOn("buildRustProver")
    from(File(projectDir, "../../target/aarch64-unknown-linux-musl/release/dzta-protected-prover"))
    into(File(projectDir, "src/main/assets/"))
}

// Guarantee the Rust binary is built & copied whenever Android builds assets
project.afterEvaluate {
    tasks.named("generateDebugAssets").configure {
        dependsOn("copyRustProverAsset")
    }
    tasks.named("generateReleaseAssets").configure {
        dependsOn("copyRustProverAsset")
    }
}