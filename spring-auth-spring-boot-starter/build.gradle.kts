description = "spring-auth starter - auto-configuration wiring core, JPA and web together"

dependencies {
    api(project(":spring-auth-core"))
    api(project(":spring-auth-jpa"))
    api(project(":spring-auth-web"))

    api("org.springframework.boot:spring-boot-autoconfigure")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    // Redis is optional: when a StringRedisTemplate is on the classpath the starter swaps the
    // in-memory rate limiter, replay guard and revocation store for their distributed variants.
    compileOnly("org.springframework.boot:spring-boot-starter-data-redis")

    // Flyway is optional too: present, the library migrates its own schema on a dedicated
    // instance; absent, the schema is the application's responsibility.
    compileOnly("org.flywaydb:flyway-core")
    compileOnly("org.springframework.boot:spring-boot-flyway")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("com.h2database:h2")

    testImplementation("org.springframework.boot:spring-boot-flyway")
    testImplementation("org.flywaydb:flyway-database-postgresql")
    testRuntimeOnly("org.postgresql:postgresql")
    testImplementation("org.testcontainers:testcontainers-postgresql")
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
}

// Fast tests do not require Docker. PostgreSQL verification is mandatory for a full check.
tasks.named<Test>("test") {
    useJUnitPlatform { excludeTags("postgres") }
}
val postgresTest by tasks.registering(Test::class) {
    description = "Runs migrations, persistence and authentication tests on real PostgreSQL"
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform { includeTags("postgres") }
    shouldRunAfter(tasks.test)
}
tasks.named("check") { dependsOn(postgresTest) }
