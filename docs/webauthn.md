# Extension WebAuthn

Cette extension reste optionnelle et ne remplace pas TOTP immédiatement.

## Contrat prévu

1. Le serveur génère un challenge aléatoire à durée courte et le lie à l’utilisateur et à l’action.
2. L’inscription vérifie l’attestation, l’origine, le RP ID et l’unicité de `credentialId`.
3. L’assertion vérifie la signature avec la clé publique persistée et refuse un compteur inférieur
   ou égal au dernier compteur accepté.
4. La mise à jour du compteur est atomique ; un échec de concurrence invalide l’assertion.
5. La révocation supprime le credential et invalide les sessions nécessitant ce facteur.

Le modèle et le port de stockage sont dans `spring-auth-core`. La vérification CBOR/WebAuthn sera
ajoutée dans un adaptateur dédié afin de maintenir le cœur indépendant du fournisseur.
