# Getting started

Integrating spring-auth into an existing Spring Boot application. Supply the user-directory
adapter and verify compatibility with the application's database and security configuration.

## 1. Add the dependency

```groovy
implementation("io.github.springauth:spring-auth-spring-boot-starter:1.0.0-SNAPSHOT")
implementation("org.springframework.boot:spring-boot-flyway")
runtimeOnly("org.flywaydb:flyway-database-postgresql")
runtimeOnly("org.postgresql:postgresql")
```

Or, when the jar is vendored into the project (`./gradlew dist` produces them):

```groovy
implementation(files("libs/spring-auth-core-1.0.0-SNAPSHOT.jar",
                     "libs/spring-auth-jpa-1.0.0-SNAPSHOT.jar",
                     "libs/spring-auth-web-1.0.0-SNAPSHOT.jar",
                     "libs/spring-auth-spring-boot-starter-1.0.0-SNAPSHOT.jar"))
```

## 2. The schema takes care of itself

The library ships its own `auth_` tables and storage adapters. The application supplies its
user-directory projection; it can use its own user model or the optional application-user store.
The library's migration history remains separate from the application's migrations.

With Spring Boot Flyway support and `flyway-database-postgresql` on the classpath it migrates itself at startup on a **dedicated Flyway
instance**: its own location (`classpath:db/springauth/migration`) and its own history table
(`flyway_schema_history_springauth`), separate from your `flyway_schema_history`. Nothing to
configure for the library's own migration history.

If the host application also manages migrations, declare its own Flyway instance with a separate
location and history table. The library already supplies a Flyway bean, so the host must not assume
that Spring Boot will create an additional default migrator. The PostgreSQL integration suite tests
both migration histories together, including overlapping V1 version numbers.

That separation is deliberate. Sharing your Flyway would mean the library's `V1` competing with
your own `V1`, and Flyway refusing to start on a duplicate version. That conflict would surface
the day you adopt the library, on a database that already has history.

The migration runs before the entity manager is built, so Hibernate finds its tables in place.

**Managing the schema yourself?** Set `spring-auth.jpa.migrate: false` and apply the SQL from your
own pipeline. It is `db/springauth/migration/V1__spring_auth_schema.sql` inside the
`spring-auth-jpa` jar, written for PostgreSQL. The complete schema is described by versions V1 through V13; apply all versions with their history, not V1 alone. UUIDs, booleans, byte arrays and large text use native PostgreSQL types. Configure a PostgreSQL datasource and use `spring.jpa.hibernate.ddl-auto=validate`.

## 3. Implement `AuthUserDirectory`

The only mandatory piece. spring-auth owns credentials, factors and sessions; your application
keeps owning its users.

```java
@Component
public class JpaAuthUserDirectory implements AuthUserDirectory {

    private final UserRepository users;

    public JpaAuthUserDirectory(UserRepository users) {
        this.users = users;
    }

    @Override
    public Optional<AuthUser> findByLogin(String login) {
        return users.findByEmailIgnoreCase(login).map(this::toAuthUser);
    }

    @Override
    public Optional<AuthUser> findById(AuthUserId id) {
        return users.findById(UUID.fromString(id.value())).map(this::toAuthUser);
    }

    private AuthUser toAuthUser(UserEntity user) {
        return AuthUser.builder(AuthUserId.of(user.getId()), user.getEmail())
                .email(user.getEmail())
                .phoneNumber(user.getPhone())
                .displayName(user.getFullName())
                .status(mapStatus(user))
                .mfaRequirement(user.isStaff() ? MfaRequirement.NOT_APPLICABLE : MfaRequirement.REQUIRED)
                .tenantId(user.getCompanyId())
                .roleCodes(user.getRoleCodes())
                .build();
    }
}
```

Both methods run on every login, so back them with indexed queries.

Get the status mapping right. Only `ACTIVE` can authenticate; everything else is refused with the
same generic error, and the precise reason lands in the login history.

## 4. Configure the two secrets

```yaml
spring-auth:
  jwt:
    private-key: ${SPRING_AUTH_JWT_PRIVATE_KEY}   # base64 PKCS#8
    public-key: ${SPRING_AUTH_JWT_PUBLIC_KEY}     # base64 X.509 SubjectPublicKeyInfo
    require-persistent-keys: true
  crypto:
    master-key: ${SPRING_AUTH_CRYPTO_KEY}         # base64, 32 bytes
```

Generate them once:

```java
String[] keys = JwtKeyProvider.exportKeyPair(JwtKeyProvider.generateKeyPair());
System.out.println("private: " + keys[0]);
System.out.println("public:  " + keys[1]);
System.out.println("crypto:  " + SecretCipher.generateMasterKey());
```

Without them the application still starts and generates ephemeral keys, with a warning. That is
fine locally and unacceptable anywhere else: every token is invalidated on restart, and, worse still,
every enrolled MFA factor becomes permanently unreadable. `require-persistent-keys: true` turns
that convenience into a startup failure, which is what you want outside your laptop.

## 5. Deliver the secrets the library produces

The library generates reset codes and invitation links; it has no mailer and no SMS gateway, so it
hands them to you.

```java
@Component
public class MyAuthMessenger implements AuthMessenger {

    private final MailSender mail;
    private final SmsGateway sms;

    @Override
    public void sendPasswordResetOtp(AuthUser user, String rawToken, String rawOtp, Instant expiresAt) {
        mail.send(user.email(), "Réinitialisation",
                "https://app.example.com/reset?token=" + rawToken);
        if (rawOtp != null) {
            sms.send(user.phoneNumber(), "Votre code : " + rawOtp);
        }
    }

    @Override
    public void sendInvitation(AuthUser user, String rawToken, Instant expiresAt) {
        mail.send(user.email(), "Activez votre compte",
                "https://app.example.com/activate?token=" + rawToken);
    }

    @Override
    public void sendAccountLockedAlert(AuthUser user, Instant lockedUntil) {
        mail.send(user.email(), "Alerte sécurité", "Votre compte a été verrouillé.");
    }
}
```

Two rules: never log the raw values, and send after the surrounding transaction commits. Delivering
a code for a request that then rolls back hands the user a code the server never stored.

Skip this and the application still starts; the startup report warns that reset codes are being
generated and thrown away.

## 6. Set the first password

Nothing else can happen until a user has credentials. Either invite them:

```java
invitationService.invite(AuthUserId.of(user.getId()));   // link goes out through AuthMessenger
```

Or set one directly, which is what a seeding routine does:

```java
passwordService.setPassword(AuthUserId.of(user.getId()), "Temporary-Pass-42!", true);
```

## 7. Try it

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"alex@example.com","password":"Temporary-Pass-42!"}'
```

Three shapes of answer, told apart by `status`:

- `AUTHENTICATED` : `tokens` holds the access and refresh tokens
- `MFA_ENROLLMENT_REQUIRED` : `intermediateToken` starts an enrolment
- `MFA_CHALLENGE_REQUIRED` : `intermediateToken` plus a TOTP code finishes the login

## 8. Protect your endpoints

Method security is on. Permissions come from the roles you assign:

```java
@GetMapping("/orders")
@PreAuthorize("hasAuthority('orders:read')")
public List<Order> list() { ... }
```

Seed the roles once at startup:

```java
roleService.seedSystemRole("ADMIN", "Administrator", null,
        Set.of("orders:read", "orders:write", "auth:roles:read", "auth:roles:write"));
```

For the few operations where a stolen session is not an acceptable risk:

```java
@PostMapping("/transfers")
@RequiresStepUp
@PreAuthorize("hasAuthority('transfers:create')")
public TransferResponse transfer(@RequestBody TransferRequest request) { ... }
```

The caller then has to send a current TOTP code in `X-Mfa-Code`, and it is consumed.

## 9. Read the startup report

At boot the library logs the settings that are safe in development and risky in production:
in-memory rate limiting, missing messenger, disabled history, and so on. An empty report reads:

```
spring-auth: started with a hardened configuration
```

## Next

- [Configuration](configuration.md) for the full property list
- [Security model](security-model.md) for what each mechanism defends against
- [Operations](operations.md) for key rotation, housekeeping and multi-instance deployment
