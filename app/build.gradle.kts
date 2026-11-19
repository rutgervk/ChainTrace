plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "nl.chaintrace.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "nl.chaintrace.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 13
        versionName = "2.3"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    // De Android-app draait exact dezelfde webapp als de webversie.
    sourceSets["main"].assets.srcDirs("../web")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.9.2")
    implementation("androidx.webkit:webkit:1.11.0")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
}
