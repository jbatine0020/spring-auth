# Building and testing

## Commands

```bash
./gradlew test                                      # fast tests, no Docker required
./gradlew :spring-auth-spring-boot-starter:postgresTest  # real PostgreSQL integration
./gradlew clean check dist                          # complete verification and distribution
./gradlew publishToMavenLocal                       # install artifacts for a local consumer
```

JDK 25 is required. Full verification requires a working Docker engine. Testcontainers creates an isolated PostgreSQL 17.4 container with a random password and cleans it up after the suite. It does not connect to an existing application database. A missing Docker engine fails the PostgreSQL task rather than silently skipping it.

If Docker is exposed through a non-default socket, set `DOCKER_HOST` to the appropriate endpoint before launching Gradle. No machine-specific socket is hardcoded in the build.

## Fast tests

The core tests cover cryptography, password rules, lockout, JWT, MFA, sessions, identity synchronization and storage contracts using single-threaded in-memory test fixtures. The starter HTTP suite uses H2 with migrations disabled; it verifies wiring, security filters, input validation and the authentication endpoints. H2 is not evidence of PostgreSQL migration compatibility.

## Real PostgreSQL verification

`SpringAuthPostgresIT` repeats the starter HTTP suite on a migrated PostgreSQL database with `ddl-auto=validate`. It adds checks for:

- All 13 library migrations, separate host history containing its own V1, and zero pending migration after a second migrate call.
- Operation in a non-default schema and seed administration permissions.
- Unique generated profile codes from concurrent transactions.
- Persistent failed-password counters after a rejected login.
- Refresh-token rotation, persistent family revocation on replay and at most one successful concurrent renewal.
- Single-consumption OTP row locking.
- TOTP enrollment, encrypted storage and single successful verification under concurrency.
- Native UUIDs, identity attributes, role collections, bytea public-key storage and large Unicode audit text.

The tests exercise real PostgreSQL transactions. They do not start a mail server, an identity server or the consuming application. Email/SMS code delivery and distributed Redis behavior depend on the host configuration and are not claimed as validated by this suite.

## Adding migrations and adapters

The initial schema currently ends at V13. Future schema changes use V14 and later; do not edit migrations after consumers have deployed them. Add assertions to the real-database suite for every schema-sensitive behavior.

Custom refresh-token stores must implement a locking lookup for rotation, separate from read-only diagnostics. Custom MFA stores must serialize the verification read and counter write. The in-memory fixtures in unit tests are not production storage adapters.

## Documentation and results

`checkDocs` checks Markdown and Java prose. The latest measured counts, scope and limitations are recorded in [validation](validation.md). A successful build of the library does not replace the consuming application's own integration and deployment checks.
