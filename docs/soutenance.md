# Présentation orale (15 min) + démo

| Minutes | Contenu |
|---|---|
| 0-2 | Problème de la PME et objectif |
| 2-5 | Architecture : 3 zones, routeur/pare-feu, outils |
| 5-9 | **Démo** (script ci-dessous) |
| 9-12 | Sécurité : règles nftables, Vault, Trivy, audit |
| 12-15 | Bilan, limites, améliorations, questions |

## Script de démo
```bash
make up                     # 1. déploiement
make test                   # 2. tests : tout est OK
docker exec client-1 dig +short @172.20.2.10 web.pme.local      # 3. DNS du LAN
docker exec web-dmz nc -w 2 172.20.2.10 53 </dev/null; echo $?  # 4. DMZ -> LAN bloqué (code <> 0)
docker stop web-dmz                                             # 5. panne simulée
#   -> Grafana : le site passe « HORS SERVICE » + alerte dans Prometheus
docker start web-dmz
```
