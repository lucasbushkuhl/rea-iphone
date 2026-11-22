plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val buildNumber = (System.getenv("VERSION_CODE") ?: "1").toInt()

android {
    namespace = "app.airscope"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.airscope"
        minSdk = 26
        targetSdk = 35
        versionCode = buildNumber
        versionName = "0.1.$buildNumber"
    }

    // One fixed signing key, kept in the repository, so each new build installs
    // over the previous one. Fine for a personal, side-loaded app.
    signingConfigs {
        create("sideload") {
            storeFile = file("../sideload.keystore")
            storePassword = "airscope"
            keyAlias = "airscope"
            keyPassword = "airscope"
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("sideload")
        }
        getByName("debug") {
            signingConfig = signingConfigs.getByName("sideload")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.webkit:webkit:1.12.1")
}
