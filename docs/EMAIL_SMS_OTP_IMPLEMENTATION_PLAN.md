# Plan des canaux OTP optionnels

Les canaux email et SMS sont des extensions optionnelles fournies par l’application consommatrice via `AuthMessenger`. La connexion locale et le TOTP ne nécessitent pas de fournisseur d’identité externe.

Les services de génération, vérification et limitation des codes sont conservés. L’application décide des méthodes activées et fournit les adaptateurs de livraison nécessaires ; aucun serveur de messagerie n’est embarqué.
