rootProject.name = "spring-auth"

include("spring-auth-core")
include("spring-auth-jpa")
include("spring-auth-web")
include("spring-auth-spring-boot-starter")

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}
