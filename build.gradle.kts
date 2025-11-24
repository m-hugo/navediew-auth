repositories {
	google()
	mavenCentral()
}
plugins {
	id("com.android.application") version "9.0.0-beta02"
	kotlin("plugin.serialization") version "2.0.0"
}
dependencies {
	implementation ("androidx.credentials:credentials:1.3.0") //no 1.4 and size bug from 1.5.0-beta01 to 1.6.0-beta03
	implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.0") //smallest version
}
android {
	namespace = "uk.navediew.authlin"
	compileSdk = 36
	defaultConfig {
		applicationId = "uk.navediew.authlin"
		minSdk = 34
		targetSdk = 36
		androidResources {
			localeFilters += listOf("en")
		}
	}
	compileOptions {
		sourceCompatibility = JavaVersion.VERSION_21
		targetCompatibility = JavaVersion.VERSION_21
	}
	kotlin {
		compilerOptions {
			jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21
		}
	}
	buildTypes {
		debug {
			isDebuggable = false
			isMinifyEnabled = true
			isShrinkResources = true
			proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
		}
	}
	lint {
		disable += "GradleDependency"
		disable += "NewerVersionAvailable"
		disable += "MissingApplicationIcon"
		disable += "SetTextI18n"
		abortOnError = false
		checkReleaseBuilds =  false
	}
}
