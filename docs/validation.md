# Validation de la version 1.0.0-SNAPSHOT

Date : 28 octobre 2026.

La commande `./gradlew --no-daemon check dist` a réussi avec JDK 25, Gradle 9.3.0 et Docker. PostgreSQL 17.4 est démarré dans un conteneur Testcontainers isolé, avec mot de passe généré à l’exécution.

| Suite | Tests exécutés | Échecs | Ignorés |
|---|---:|---:|---:|
| spring-auth-core | 139 | 0 | 0 |
| Starter HTTP sur H2 | 11 | 0 | 0 |
| Starter et persistance sur PostgreSQL | 21 | 0 | 0 |
| Total | 171 | 0 | 0 |

## Vérifications PostgreSQL

- Les 13 migrations s’exécutent sur une base vierge ; une nouvelle exécution n’applique aucune migration supplémentaire.
- Hibernate valide les mappings sur les tables migrées, sans `create` ni `update` automatique.
- Le schéma de test non standard fonctionne ; l’application hôte peut exécuter sa propre V1 dans un historique Flyway séparé.
- Les codes de profil générés par une séquence sont uniques sous concurrence.
- Connexion par mot de passe, refus des mauvais identifiants et des accès anonymes, renouvellement et rejeu sont vérifiés sur les endpoints HTTP.
- Les compteurs d’échec sont persistés même lorsque l’authentification est refusée.
- Un même refresh token ne peut pas être renouvelé deux fois simultanément ; sa réutilisation révoque durablement les jetons de la famille.
- L’enrôlement TOTP persiste un secret chiffré ; deux validations concurrentes d’un même code ne réussissent pas ensemble.
- La consommation d’un OTP est protégée par verrou de ligne.
- Les identités, noms Unicode et rôles sont relus après transaction ; les clés publiques binaires utilisent bytea et le journal accepte de longs textes Unicode.

## Corrections couvertes

Le stockage des refresh tokens et des facteurs MFA expose une lecture verrouillée séparée des lectures diagnostiques. La révocation pour rejeu est conservée lors d’une exception de session attendue. Les tests ont reproduit les doubles validations et l’annulation de la révocation avant correction.

## Artefacts et limites

Quatre JAR principaux sont disponibles dans `build/dist`, accompagnés des sources et de la Javadoc. Ils ne contiennent pas d’ancien nom de projet ou d’adaptateur d’annuaire. Aucune publication distante n’a été effectuée.

Les modules JPA et web n’ont pas de tâche de test autonome avec des cas propres ; leurs chemins concernés sont exercés par la suite du starter. Les tests ne constituent pas une conversion en place d’une ancienne base d’un autre moteur, un test de charge, une validation de livraison email/SMS ou une qualification Redis distribuée. L’application consommatrice doit vérifier sa configuration d’identité, ses sessions, ses migrations et son déploiement.
