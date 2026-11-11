# Architecture

```mermaid
flowchart TB
    Internet((Internet)) -->|8080/8443 → DNAT| FW
    subgraph Hôte Docker
        FW[router-fw<br/>nftables<br/>.1.1 / .2.1 / .3.1]
        subgraph dmz-net 172.20.1.0/24
            WEB[web-dmz<br/>Nginx .1.10]
        end
        subgraph lan-net 172.20.2.0/24
            DNS[dns-lan<br/>dnsmasq .2.10]
            C1[client-1 .2.100]
            C2[client-2 .2.101]
        end
        subgraph mgmt-net 172.20.3.0/24
            PROM[Prometheus .3.10]
            GRAF[Grafana .3.11]
            BB[blackbox .3.20]
        end
        FW --- WEB
        FW --- DNS
        FW --- PROM
        BB -.sondes HTTP/DNS.-> FW
        PROM --> BB
        GRAF --> PROM
    end
    Dev[Poste admin] -->|git push| Git --> Jenkins --> Sonar[SonarQube] & Trivy
```

## Comment les zones communiquent
Chaque service ajoute au démarrage une route vers les autres zones **via router-fw** (`docker/common/set-routes.sh`).
Le routeur applique les règles nftables. La politique par défaut est `drop`.

## Chaîne CI/CD
Git → Jenkins (lint → SonarQube → build → Trivy → déploiement test + tests → validation manuelle → prod) → notification mail en cas d'échec.
