# Plan de réutilisation de spring-auth

## Périmètre de cette version

- Nom de dépôt, modules, artefacts et propriétés : `spring-auth`.
- Groupe Maven et packages Java : `io.github.springauth`.
- Quatre modules : core, jpa, web et spring-boot-starter.
- Connexion par mot de passe, JWT, MFA, rôles, permissions et sessions conservés.
- SPI génériques d’identité conservées ; aucun fournisseur d’annuaire imposé.
- Tests du miroir d’identité conservés dans le module core.
- Configurations et exemples désolidarisés d’une application métier précise.

## Persistance PostgreSQL

Les 13 migrations ont été portées, la requête de séquence utilise PostgreSQL et le mapping des clés binaires est adapté à bytea. Une suite `postgresTest` vérifie les migrations, les mappings validés par Hibernate, la coexistence avec les migrations consommatrices et les parcours d’authentification sur une base PostgreSQL 17.4 temporaire. Les applications choisissent leurs comptes, permissions, canaux MFA et procédures de récupération. La compatibilité de chaque consommateur reste à vérifier par ses tests d’intégration et sa propre configuration d’identité, de sessions et de déploiement.

## Validation

`./gradlew clean check dist` compile les modules, exécute les tests et prépare les artefacts. Les résultats effectifs de la validation sont consignés dans le compte rendu de livraison ; ce plan ne préjuge pas de leur réussite.
