# spring-auth

Bibliothèque Java et starter Spring Boot réutilisables pour l’authentification par mot de passe, le MFA, les sessions, les rôles et les permissions.

## Modules

```text
spring-auth-core/                 Modèles, services, JWT, MFA, ports et SPI
spring-auth-jpa/                  Adaptateurs de persistance et migrations
spring-auth-web/                  Contrôleurs REST, filtres et autorisation HTTP
spring-auth-spring-boot-starter/   Auto-configuration et adaptateurs Redis optionnels
```

Les packages Java et le groupe Maven sont `io.github.springauth`. Les propriétés utilisent le préfixe `spring-auth`. La bibliothèque est intégrée à l’application consommatrice ; elle ne démarre pas de serveur indépendant.

## Construction

Prérequis : JDK 25 et Gradle Wrapper fourni. Le BOM de référence est Spring Boot 4.1.0. Docker est nécessaire pour la vérification PostgreSQL de `check` et `dist`.

```bash
./gradlew clean check dist
./gradlew publishToMavenLocal
```

Les JAR distribuables sont produits dans `build/dist`. La version initiale de ce dépôt est `1.0.0-SNAPSHOT`. Les coordonnées ne sont pas annoncées comme publiées sur un registre distant.

## Intégration

Après publication locale :

```kotlin
repositories { mavenLocal(); mavenCentral() }
dependencies {
    implementation("io.github.springauth:spring-auth-spring-boot-starter:1.0.0-SNAPSHOT")
}
```

L’application fournit `AuthUserDirectory` pour ses comptes, configure ses clés JWT et sa clé de chiffrement, attribue les rôles et définit ses permissions. Les comptes métier et les fournisseurs d’identité sont sous sa responsabilité. Aucune intégration d’annuaire n’est embarquée. Les SPI d’identité génériques sont conservées pour les extensions propres à chaque application.

Les canaux email/SMS sont optionnels via `AuthMessenger`. Redis fournit les mécanismes distribués optionnels. Ne pas annoncer la livraison d’un code sans adaptateur de messagerie effectif.

## Persistance actuelle

Le module JPA cible PostgreSQL : 13 migrations Flyway, UUID et booléens natifs, dates avec fuseau, clés binaires en `bytea` et textes longs en `text`. La génération des codes de profil utilise une séquence PostgreSQL. Les tests réels sont exécutés avec PostgreSQL 17.4 dans un conteneur temporaire, sans génération automatique des tables par Hibernate.

L’application consommatrice fournit le pilote PostgreSQL et les dépendances Flyway si elle active les migrations :

```kotlin
implementation("org.springframework.boot:spring-boot-flyway")
runtimeOnly("org.flywaydb:flyway-database-postgresql")
runtimeOnly("org.postgresql:postgresql")
```

Les migrations constituent le schéma initial de cette bibliothèque encore non publiée. Elles ne permettent pas de migrer sur place une ancienne base d’un autre moteur. La bibliothèque ne contient pas de pilote ou migration pour cet autre moteur. Le cœur et les ports restent remplaçables pour d’autres solutions de persistance.

Le stockage des jetons de renouvellement et des facteurs MFA utilise des lectures verrouillées pour les opérations sensibles. Les implémentations personnalisées de `RefreshTokenStore` et `MfaCredentialStore` doivent respecter les nouveaux contrats `findByTokenHashForUpdate` et `findByUserIdForUpdate` au sein d’une transaction. Les lectures diagnostiques restent séparées.

## Documentation

- [Démarrage et intégration](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [API](docs/api.md)
- [Modèle de sécurité](docs/security-model.md)
- [Plan de réutilisation](IMPLEMENTATION_PLAN.md)
- [Résultats de validation](docs/validation.md)

Les migrations ne doivent pas être modifiées après livraison dans un environnement consommateur. Ne jamais versionner de mot de passe, clé privée, secret MFA ou jeton. Les autorisations sont toujours appliquées côté backend.
