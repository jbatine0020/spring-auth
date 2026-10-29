plugins {
    `java-library`
    `maven-publish`
}

// Version of the library. Bump on every release - consumers pin this coordinate.
val libraryVersion = "1.0.0-SNAPSHOT"
val springBootVersion = "4.1.0"

allprojects {
    group = "io.github.springauth"
    version = libraryVersion
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "maven-publish")

    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(25)
        }
        // Ship sources and javadoc so consumers get inline documentation in their IDE,
        // even when the jar is dropped into a libs/ folder rather than resolved from a repository.
        withSourcesJar()
        withJavadocJar()
    }

    dependencies {
        // The Spring Boot BOM aligns every Spring/Jackson/Nimbus version with what the
        // consuming application already has on its classpath. The Boot plugin itself is
        // deliberately NOT applied: this is a library, not an executable application.
        add("api", platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
        // The BOM does not reach the annotation processor path on its own, and the configuration
        // processor would otherwise resolve without a version.
        add("annotationProcessor", platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))

        add("testImplementation", "org.junit.jupiter:junit-jupiter")
        add("testImplementation", "org.assertj:assertj-core")
        add("testImplementation", "org.mockito:mockito-core")
        add("testImplementation", "org.mockito:mockito-junit-jupiter")
        add("testRuntimeOnly", "org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
        options.compilerArgs.add("-parameters")
    }

    tasks.withType<Javadoc> {
        options.encoding = "UTF-8"
        (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
    }

    tasks.withType<Test> {
        useJUnitPlatform()
        testLogging {
            events("failed")
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
    }

    publishing {
        publications {
            create<MavenPublication>("maven") {
                from(components["java"])
                pom {
                    name.set(project.name)
                    description.set("Authentication, MFA and session security building blocks for Spring Boot")
                    licenses {
                        license {
                            name.set("Proprietary")
                        }
                    }
                }
            }
        }
    }
}

/**
 * Fails the build when prose drifts from the writing rules of this project.
 *
 * The em dash is banned everywhere: Markdown, Javadoc, comments and the user-facing strings
 * the library emits. Javadoc ships in the -javadoc jar and shows up in a consumer's IDE, so it
 * is documentation like any other. Unfinished-work markers are refused in the same sweep.
 *
 * Both rules are trivial to reintroduce by hand, which is exactly why they are checked by the
 * build rather than by good intentions.
 */
tasks.register("checkDocs") {
    group = "verification"
    description = "Fails on an em dash or an unfinished-work marker in any Markdown or Java file"

    val proseFiles = fileTree(rootDir) {
        include("**/*.md", "**/*.java")
        exclude("**/build/**", "**/.git/**")
    }
    inputs.files(proseFiles)
    // No output to declare, so the task is told explicitly it can be considered up to date.
    outputs.upToDateWhen { true }

    // Assembled rather than written literally, so this task does not flag its own source when
    // the check is later widened to Kotlin build scripts.
    val markers = listOf("TO" + "DO", "FIX" + "ME")

    doLast {
        val problems = mutableListOf<String>()
        proseFiles.forEach { file ->
            file.readLines().forEachIndexed { index, line ->
                val where = "${file.relativeTo(rootDir)}:${index + 1}"
                if (line.contains('\u2014')) {
                    problems += "$where em dash: ${line.trim()}"
                }
                if (markers.any { line.contains(it) }) {
                    problems += "$where unfinished-work marker: ${line.trim()}"
                }
            }
        }
        if (problems.isNotEmpty()) {
            throw GradleException(
                "Prose check failed with ${problems.size} problem(s):\n" +
                    problems.joinToString("\n") { "  $it" })
        }
        logger.lifecycle("checkDocs: ${proseFiles.files.size} Markdown and Java files clean")
    }
}

tasks.named("check") { dependsOn("checkDocs") }

/**
 * Collects every module jar (plus sources jars) into build/dist so the library can be
 * dropped into a consumer's libs/ folder. Run: ./gradlew dist
 */
tasks.register<Copy>("dist") {
    group = "distribution"
    description = "Copies all module jars into build/dist for jar-embedded consumption"
    subprojects.forEach { module ->
        dependsOn("${module.path}:build")
        from(module.layout.buildDirectory.dir("libs"))
    }
    into(layout.buildDirectory.dir("dist"))
}
