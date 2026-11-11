#!/usr/bin/env python3
"""Tests de connectivité NetDevOps : DNAT, DNS, règles du pare-feu, supervision."""
import json
import ssl
import subprocess
import sys
import time
import urllib.request

WEB_IP = "172.20.1.10"
DNS_IP = "172.20.2.10"
MGMT_IP = "172.20.3.10"
PROM_URL = "http://127.0.0.1:9090/api/v1/query?query=probe_success"


def run(cmd, timeout=15):
    """Exécute une commande et renvoie (code retour, sortie texte)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return res.returncode, (res.stdout + res.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "délai dépassé"


def docker_exec(container, shell_cmd, timeout=15):
    """Exécute une commande shell dans un conteneur."""
    return run(["docker", "exec", container, "sh", "-c", shell_cmd], timeout)


def http_status(url):
    """Renvoie le code HTTP d'une URL (certificat auto-signé accepté), ou 0 si échec."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=5, context=ctx) as resp:  # nosec B310
            return resp.status
    except OSError:
        return 0


def test_firewall_loaded():
    """Les règles nftables sont chargées avec une politique par défaut 'drop'."""
    code, out = docker_exec("router-fw", "nft list ruleset")
    return code == 0 and "policy drop" in out, "policy drop présente" if code == 0 else out


def test_dnat_http():
    """Internet -> router-fw:8080 -> web-dmz (DNAT HTTP)."""
    status = http_status("http://127.0.0.1:8080/")
    return status == 200, f"HTTP {status}"


def test_dnat_https():
    """Internet -> router-fw:8443 -> web-dmz (DNAT HTTPS)."""
    status = http_status("https://127.0.0.1:8443/")
    return status == 200, f"HTTPS {status}"


def test_dns_resolution():
    """Le DNS du LAN résout web.pme.local vers l'IP du serveur web."""
    code, out = docker_exec("client-1", f"dig +short +time=2 +tries=1 @{DNS_IP} web.pme.local")
    return code == 0 and out == WEB_IP, out or "pas de réponse"


def test_lan_to_web():
    """Un poste LAN atteint le site web par son nom (DNS + routage + pare-feu)."""
    cmd = "curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://web.pme.local/"
    code, out = docker_exec("client-1", cmd, 10)
    return code == 0 and out == "200", f"HTTP {out}"


def test_dmz_to_lan_blocked():
    """La DMZ ne peut pas ouvrir de connexion vers le LAN."""
    ctrl, _ = docker_exec("web-dmz", "nc -w 2 127.0.0.1 80 </dev/null")
    code, _ = docker_exec("web-dmz", f"nc -w 2 {DNS_IP} 53 </dev/null", 10)
    return ctrl == 0 and code != 0, "bloqué" if code != 0 else "NON bloqué"


def test_lan_to_mgmt_blocked():
    """Le LAN ne peut pas atteindre la zone Management."""
    ctrl, _ = docker_exec("client-1", f"nc -z -w 2 {DNS_IP} 53")
    code, _ = docker_exec("client-1", f"nc -z -w 2 {MGMT_IP} 9090", 10)
    return ctrl == 0 and code != 0, "bloqué" if code != 0 else "NON bloqué"


def test_monitoring():
    """Prometheus voit toutes les sondes en succès (ignoré si la supervision est absente)."""
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(PROM_URL, timeout=5) as resp:  # nosec B310
                data = json.load(resp)
        except OSError:
            return None, "supervision non déployée"
        values = [r["value"][1] for r in data["data"]["result"]]
        if values and all(v == "1" for v in values):
            return True, f"{len(values)} sondes OK"
        time.sleep(5)
    return False, "des sondes sont en échec"


TESTS = [
    test_firewall_loaded,
    test_dnat_http,
    test_dnat_https,
    test_dns_resolution,
    test_lan_to_web,
    test_dmz_to_lan_blocked,
    test_lan_to_mgmt_blocked,
    test_monitoring,
]


def main():
    """Lance tous les tests, affiche un tableau, renvoie 1 si un test échoue."""
    failures = 0
    print(f"{'TEST':<62} {'RÉSULTAT':<8} DÉTAIL")
    for test in TESTS:
        ok, detail = test()
        label = "SKIP" if ok is None else ("OK" if ok else "ÉCHEC")
        failures += 1 if ok is False else 0
        print(f"{test.__doc__:<62} {label:<8} {detail}")
    print(f"\n{failures} échec(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
