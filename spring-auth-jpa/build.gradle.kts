description = "spring-auth JPA - PostgreSQL persistence adapters and Flyway migrations"

dependencies {
    api(project(":spring-auth-core"))
    api("org.springframework.boot:spring-boot-starter-data-jpa")

    implementation("org.slf4j:slf4j-api")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.h2database:h2")
}
