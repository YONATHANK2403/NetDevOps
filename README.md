# NetDevOps : automatisation d'une infrastructure réseau segmentée

Une PME a 3 zones réseau : **DMZ** (site web Nginx), **LAN** (DNS dnsmasq), **Management** (supervision).
Tout est décrit dans Git, déployé par Ansible, isolé avec Docker, contrôlé par Jenkins, vérifié par SonarQube et Trivy, surveillé par Prometheus et Grafana.

## Démarrage rapide

Prérequis : Linux, Docker 24+ avec Compose v2, `make`, `openssl`. (Ansible est facultatif pour le premier lancement.)

```bash
# 1) Lancer la pile (réseaux, services, pare-feu, supervision)
make up
# 2) Vérifier que tout fonctionne (DNAT, DNS, pare-feu, sondes)
make test
# 3) Ouvrir : site  http://localhost:8080 | https://localhost:8443 | Grafana http://localhost:3000 | Prometheus http://localhost:9090
```

Variante « automatisée » (génère les configs depuis des variables, secrets chiffrés) :

```bash
pip install ansible-core
cd ansible
cp group_vars/all/vault.yml.example group_vars/all/vault.yml   # mettre de vrais mots de passe
ansible-vault encrypt group_vars/all/vault.yml
ansible-playbook playbooks/site.yml --ask-vault-pass            # --tags config : génère seulement les fichiers
```

Outils CI/CD (Jenkins sur http://localhost:8081, SonarQube sur http://localhost:9000) :

```bash
sudo sysctl -w vm.max_map_count=262144   # requis par SonarQube
make tools-up
```

Dans Jenkins : créer 2 identifiants (`sonar-token` = texte secret, `vault-pass` = fichier contenant le mot de passe Vault), puis un job « Pipeline from SCM » pointant sur ce dépôt.

## Les 5 étapes du projet

| # | Étape | Où c'est dans le dépôt |
|---|---|---|
| 1 | Socle Docker : 3 réseaux, web, DNS, routeur, postes clients | `docker-compose.yml`, `docker/` |
| 2 | Pare-feu nftables + tests de connectivité | `docker/router-fw/nftables.conf`, `scripts/check_stack.py` |
| 3 | Automatisation Ansible (rôles, variables, Vault) | `ansible/` |
| 4 | Pipeline CI/CD (Jenkins, SonarQube, Trivy) | `Jenkinsfile`, `docker-compose.tools.yml`, `docker/jenkins/` |
| 5 | Supervision, audit sécurité, documentation | `docker-compose.monitoring.yml`, `docker/monitoring/`, `docs/` |

## Schéma

| Zone | Réseau | Machines |
|---|---|---|
| DMZ | 172.20.1.0/24 | router-fw `.1`, web-dmz `.10` |
| LAN | 172.20.2.0/24 | router-fw `.2.1`, dns-lan `.10`, client-1 `.100`, client-2 `.101` |
| MGMT | 172.20.3.0/24 | router-fw `.3.1`, prometheus `.10`, grafana `.11`, blackbox `.20`, node-exporter `.30` |

Règles du pare-feu : Internet → web (80/443) ; LAN → web ; MGMT → web et DNS. **Tout le reste est bloqué** (DMZ → LAN, LAN → MGMT…).

## Limites connues (version minimale)

- Une seule machine hôte : « test » et « prod » utilisent les mêmes adresses IP. Le pipeline teste, démonte, puis déploie en prod après validation manuelle.
- Prometheus et Grafana sont deux conteneurs (et non un seul « monitoring »).
- Les ports 8080/8443 sont utilisés à la place de 80/443 pour ne pas demander les droits root.
- Voir `docs/audit-securite.md` pour les points faibles et les corrections.
