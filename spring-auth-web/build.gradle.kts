description = "spring-auth web - REST endpoints, security filter chain, filters and interceptors"

dependencies {
    api(project(":spring-auth-core"))
    api("org.springframework.boot:spring-boot-starter-web")
    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    api("org.springframework.boot:spring-boot-starter-validation")
    compileOnly("io.swagger.core.v3:swagger-annotations-jakarta:2.2.30")

    implementation("org.slf4j:slf4j-api")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}
