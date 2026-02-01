@file:Suppress("UnstableApiUsage")

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.net.URL
import java.security.MessageDigest

val pkg: String = providers.gradleProperty("wireguardPackageName").get()
val namespacePkg: String = providers.gradleProperty("wireguardNamespace").orNull ?: "com.wireguard.android"

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.kapt)
}

android {
    compileSdk = 36
    buildFeatures {
        buildConfig = true
        dataBinding = true
        viewBinding = true
    }
    namespace = namespacePkg
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("generated/jniLibs"))
    defaultConfig {
        applicationId = pkg
        minSdk = 24
        targetSdk = 36
        versionCode = providers.gradleProperty("wireguardVersionCode").get().toInt()
        versionName = providers.gradleProperty("wireguardVersionName").get()
        buildConfigField("int", "MIN_SDK_VERSION", minSdk.toString())
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles("proguard-android-optimize.txt")
            packaging {
                resources {
                    excludes += "DebugProbesKt.bin"
                    excludes += "kotlin-tooling-metadata.json"
                    excludes += "META-INF/*.version"
                }
            }
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        create("googleplay") {
            initWith(getByName("release"))
            matchingFallbacks += "release"
        }
    }
    androidResources {
        generateLocaleConfig = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
    lint {
        disable += "LongLogTag"
        warning += "MissingTranslation"
        warning += "ImpliedQuantity"
    }
}

dependencies {
    implementation(project(":tunnel"))
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.annotation)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.coordinatorlayout)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.preference.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.google.material)
    implementation(libs.zxing.android.embedded)
    implementation(libs.kotlinx.coroutines.android)
    coreLibraryDesugaring(libs.desugarJdkLibs)
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:unchecked")
    options.isDeprecation = true
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions.jvmTarget = JvmTarget.JVM_17
}

val wstunnelArm64TarUrl = providers.gradleProperty("wstunnelArm64TarUrl").orNull
val wstunnelChecksumsUrl = providers.gradleProperty("wstunnelChecksumsUrl").orNull
val wstunnelArm64Sha256 = providers.gradleProperty("wstunnelArm64Sha256").orNull
val wstunnelArm64ExecutableName = providers.gradleProperty("wstunnelArm64ExecutableName").orNull
val buildDirFile = layout.buildDirectory.get().asFile

fun sha256Of(file: java.io.File): String {
    val md = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buf = ByteArray(8192)
        var read = input.read(buf)
        while (read > 0) {
            md.update(buf, 0, read)
            read = input.read(buf)
        }
    }
    return md.digest().joinToString("") { "%02x".format(it) }
}

val downloadWstunnelLibs = tasks.register("downloadWstunnelLibs") {
    description = "Download embedded wstunnel libs into build/generated/jniLibs"
    group = "build setup"
    doLast {
        val tarUrl = wstunnelArm64TarUrl ?: throw GradleException("Missing gradle property: wstunnelArm64TarUrl")
        val checksumsUrl = wstunnelChecksumsUrl

        val tarFile = file("$buildDirFile/tmp/wstunnel/wstunnel_android_arm64.tar.gz")
        tarFile.parentFile.mkdirs()

        URL(tarUrl).openStream().use { input: java.io.InputStream ->
            tarFile.outputStream().use { output: java.io.OutputStream ->
                input.copyTo(output)
            }
        }

        val expectedSha = if (!wstunnelArm64Sha256.isNullOrBlank()) {
            wstunnelArm64Sha256
        } else {
            val url = checksumsUrl ?: throw GradleException("Missing gradle property: wstunnelChecksumsUrl (or set wstunnelArm64Sha256)")
            val checksumsText = URL(url).readText()
            val tarName = tarUrl.substringAfterLast('/')
            val line = checksumsText.lineSequence().firstOrNull { it.contains(tarName) }
                ?: throw GradleException("Checksum for $tarName not found in checksums.txt")
            line.trim().split(Regex("\\s+")).firstOrNull()
                ?: throw GradleException("Malformed checksum line for $tarName")
        }

        val actualSha = sha256Of(tarFile)
        if (!actualSha.equals(expectedSha, ignoreCase = true)) {
            tarFile.delete()
            throw GradleException("wstunnel arm64 sha256 mismatch. expected=$expectedSha actual=$actualSha")
        }

        val extractDir = file("$buildDirFile/tmp/wstunnel/extracted")
        extractDir.deleteRecursively()
        extractDir.mkdirs()
        copy {
            from(tarTree(resources.gzip(tarFile)))
            into(extractDir)
        }

        val exeName = wstunnelArm64ExecutableName ?: "libwstunnel.so"
        val foundLib = extractDir.walkTopDown().firstOrNull { it.name == exeName }
            ?: throw GradleException("$exeName not found in $tarFile")

        val outDir = file("$buildDirFile/generated/jniLibs/arm64-v8a")
        outDir.mkdirs()
        foundLib.copyTo(file("$buildDirFile/generated/jniLibs/arm64-v8a/libwstunnel.so"), overwrite = true)
    }
}

tasks.named("preBuild") {
    dependsOn(downloadWstunnelLibs)
}
