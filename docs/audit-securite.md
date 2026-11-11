# Rapport d'audit sécurité

## Mesures déjà en place
| Mesure | Où |
|---|---|
| Politique pare-feu « tout interdit », flux autorisés un par un, paquets invalides rejetés | `nftables.conf` |
| Refus journalisés (limités à 5/min) | `nftables.conf` |
| Zones séparées : DMZ ne peut pas joindre LAN ni MGMT | `nftables.conf`, testé par `check_stack.py` |
| Nginx : version masquée, TLS 1.2+, en-têtes de sécurité | `default.conf.j2` |
| Secrets chiffrés (Ansible Vault), `.env` en `0600` et ignoré par Git | `ansible/`, `.gitignore` |
| Grafana, Prometheus, Jenkins, SonarQube publiés sur `127.0.0.1` uniquement | fichiers compose |
| Inscription Grafana et télémétrie désactivées | `docker-compose.monitoring.yml` |
| Versions d'images fixées | fichiers compose |
| Lint + analyse SonarQube + scan Trivy avant chaque déploiement | `Jenkinsfile` |

## Points faibles et corrections proposées
| # | Point faible | Gravité | Correction recommandée |
|---|---|---|---|
| 1 | Jenkins a accès au socket Docker (équivaut à root sur l'hôte) | Élevée | Agent de build isolé, Docker rootless ou proxy de socket |
| 2 | Jenkins tourne en `root` | Élevée | Utilisateur `jenkins` + groupe `docker` |
| 3 | `NET_ADMIN` donné à web, DNS, clients et blackbox pour ajouter une route | Moyenne | En production : vrais routeurs/VLAN, routes sans capacité |
| 4 | Certificat auto-signé | Moyenne | Autorité interne ou Let's Encrypt |
| 5 | HTTP non redirigé vers HTTPS | Moyenne | Ajouter une redirection 301 |
| 6 | L'IP source des visiteurs est masquée (masquerade) : les logs Nginx voient `172.20.1.1` | Moyenne | `X-Forwarded-For` ou PROXY protocol |
| 7 | Mots de passe dans `.env` en clair sur le disque | Moyenne | Docker secrets ou coffre-fort (Vault) |
| 8 | Pas d'authentification ni de TLS sur Prometheus | Faible (accès local) | Reverse proxy avec authentification |
| 9 | Trivy bloque seulement les CVE `CRITICAL` | Faible | Passer à `HIGH,CRITICAL` une fois les images propres |
| 10 | Images non épinglées par empreinte (digest) | Faible | Épingler `image@sha256:…` |
| 11 | Pas de limitation de débit sur Nginx | Faible | `limit_req_zone` |
| 12 | Test et prod sur le même hôte et mêmes IP | Faible | Deux hôtes ou sous-réseaux paramétrés |
