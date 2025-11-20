plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    kotlin("plugin.serialization")
}
android {
    namespace = "uk.navediew.kotlinauth"
    compileSdk = 36
    defaultConfig {
        applicationId = "uk.navediew.kotlinauth"
        minSdk = 34
        targetSdk = 36
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
			isDebuggable = false
        }
    }
	kotlinOptions {
        jvmTarget = JavaVersion.VERSION_1_8.toString()
    }
}
dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation ("androidx.credentials:credentials:1.3.0")
    implementation ("androidx.biometric:biometric-ktx:1.2.0-alpha05")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.0")
}
//size: 1412kB (du -BKB  app/build/outputs/apk/debug/app-debug.apk) but 2MB in android
