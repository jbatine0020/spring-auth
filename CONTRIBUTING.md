# Contribuer à spring-auth

Utiliser des branches descriptives et des commits Conventional Commits, par exemple `refactor(identity): simplify provider integration`. Les règles de protection de branches sont définies sur le dépôt hébergeant le projet.

Avant livraison, exécuter :

```bash
./gradlew clean check dist
```

Documenter les modifications de SPI, propriétés, API, migrations et comportements de sécurité. Une migration déjà livrée ne doit pas être réécrite. Tout changement d’authentification, de MFA ou de session doit conserver les tests de concurrence et d’autorisation pertinents.

Ne pas versionner de secret, de jeton, de clé privée, de mot de passe ou de donnée personnelle réelle. Les comptes, règles métier, fournisseurs d’identité et canaux de livraison relèvent des applications consommatrices.
