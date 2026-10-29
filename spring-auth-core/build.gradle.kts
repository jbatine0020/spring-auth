description = "spring-auth core - domain model, crypto, JWT issuance and authentication services"

dependencies {
    // Password hashing contract (PasswordEncoder / BCrypt). spring-security-crypto is a
    // standalone artifact: it drags in neither the servlet stack nor the filter chain.
    api("org.springframework.security:spring-security-crypto")

    // JOSE / JWT signing and verification. The Spring Boot BOM does not manage this coordinate
    // (Spring Security pulls it transitively), so it is pinned to the version Spring Security 6.5
    // resolves. A consuming application already on a newer one wins through Gradle conflict
    // resolution, which is the intended behaviour.
    api("com.nimbusds:nimbus-jose-jwt:9.37.4")

    // Configuration properties binding. The core exposes AuthProperties; bean wiring itself
    // lives in the starter, so the core stays free of stereotype annotations.
    api("org.springframework.boot:spring-boot")

    // @Transactional on the services. Authentication needs precise rollback semantics - a failed
    // login must still commit its attempt counter - and that cannot be delegated to the caller.
    api("org.springframework:spring-tx")

    implementation("org.slf4j:slf4j-api")

    testImplementation("org.slf4j:slf4j-simple")
}
