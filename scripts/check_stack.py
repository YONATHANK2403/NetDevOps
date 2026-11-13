#!/usr/bin/env python3
"""Tests de connectivité NetDevOps : DNAT, DNS, règles du pare-feu, supervision."""
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request

# Paramètres d'environnement : valeurs par défaut conservées pour PROD.
WEB_IP = os.environ.get("NETDEVOPS_WEB_IP", "172.20.1.10")
DNS_IP = os.environ.get("NETDEVOPS_DNS_IP", "172.20.2.10")
MGMT_IP = os.environ.get("NETDEVOPS_MGMT_IP", "172.20.3.10")

DOMAIN = os.environ.get("NETDEVOPS_DOMAIN", "pme.local")
WEB_FQDN = f"web.{DOMAIN}"

ROUTER_CONTAINER = os.environ.get("NETDEVOPS_ROUTER_CONTAINER", "router-fw")
WEB_CONTAINER = os.environ.get("NETDEVOPS_WEB_CONTAINER", "web-dmz")
CLIENT_CONTAINER = os.environ.get("NETDEVOPS_CLIENT_CONTAINER", "client-1")
PROMETHEUS_CONTAINER = os.environ.get("NETDEVOPS_PROMETHEUS_CONTAINER", "prometheus")

HTTP_PORT = os.environ.get("NETDEVOPS_HTTP_PORT", "8080")
HTTPS_PORT = os.environ.get("NETDEVOPS_HTTPS_PORT", "8443")
MGMT_PORT = os.environ.get("NETDEVOPS_PROMETHEUS_PORT", "9090")
DNAT_HOST = os.environ.get("NETDEVOPS_TEST_HOST", "127.0.0.1")

EXPECTED_PROBES = {
    "blackbox-dns",
    "blackbox-http",
    "blackbox-https",
}


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
    code, out = docker_exec(ROUTER_CONTAINER, "nft list ruleset")
    return code == 0 and "policy drop" in out, "policy drop présente" if code == 0 else out


def test_dnat_http():
    """Accès HTTP externe via le port DNAT configuré."""
    status = http_status(f"http://{DNAT_HOST}:{HTTP_PORT}/")
    return status == 200, f"HTTP {status}"


def test_dnat_https():
    """Accès HTTPS externe via le port DNAT configuré."""
    status = http_status(f"https://{DNAT_HOST}:{HTTPS_PORT}/")
    return status == 200, f"HTTPS {status}"


def test_dns_resolution():
    """Le DNS du LAN résout le nom Web configuré vers son adresse IP."""
    code, out = docker_exec(CLIENT_CONTAINER, f"dig +short +time=2 +tries=1 @{DNS_IP} {WEB_FQDN}")
    return code == 0 and out == WEB_IP, out or "pas de réponse"


def test_lan_to_web():
    """Un poste LAN atteint le site web par son nom (DNS + routage + pare-feu)."""
    cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 http://{WEB_FQDN}/"
    code, out = docker_exec(CLIENT_CONTAINER, cmd, 10)
    return code == 0 and out == "200", f"HTTP {out}"


def test_dmz_to_lan_blocked():
    """La DMZ ne peut pas ouvrir de connexion vers le LAN."""
    ctrl, _ = docker_exec(WEB_CONTAINER, "nc -w 2 127.0.0.1 80 </dev/null")
    code, _ = docker_exec(WEB_CONTAINER, f"nc -w 2 {DNS_IP} 53 </dev/null", 10)
    return ctrl == 0 and code != 0, "bloqué" if code != 0 else "NON bloqué"


def test_lan_to_mgmt_blocked():
    """Le LAN ne peut pas atteindre la zone Management."""
    ctrl, _ = docker_exec(CLIENT_CONTAINER, f"nc -z -w 2 {DNS_IP} 53")
    code, _ = docker_exec(CLIENT_CONTAINER, f"nc -z -w 2 {MGMT_IP} {MGMT_PORT}", 10)
    return ctrl == 0 and code != 0, "bloqué" if code != 0 else "NON bloqué"


def parse_probe_values(response):
    """Extrait les valeurs des trois sondes attendues depuis la réponse JSON."""
    try:
        data = json.loads(response)
    except json.JSONDecodeError:
        return None, "réponse Prometheus JSON invalide"

    if data.get("status") != "success":
        return None, f"API Prometheus en erreur : {data}"

    results = data.get("data", {}).get("result", [])
    probe_values = {}

    for item in results:
        metric = item.get("metric", {})
        job = metric.get("job")
        value = item.get("value", [])

        if job in EXPECTED_PROBES and len(value) > 1:
            probe_values[job] = value[1]

    return probe_values, None


def test_monitoring():
    """Prometheus confirme les trois sondes DNS, HTTP et HTTPS."""
    present, _ = run(["docker", "inspect", PROMETHEUS_CONTAINER], timeout=5)
    if present != 0:
        return None, "supervision non déployée"

    query = (
        "wget -qO- --timeout=5 "
        "'http://127.0.0.1:9090/api/v1/query?query=probe_success'"
    )
    deadline = time.time() + 60
    last_detail = "aucune sonde disponible"

    while time.time() < deadline:
        code, out = docker_exec(PROMETHEUS_CONTAINER, query, 10)
        if code != 0:
            return False, f"API Prometheus inaccessible : {out}"

        probe_values, error = parse_probe_values(out)
        if error:
            return False, error

        missing = EXPECTED_PROBES - probe_values.keys()
        failed = {
            job for job in EXPECTED_PROBES
            if job in probe_values and probe_values[job] != "1"
        }

        if not missing and not failed:
            return True, f"{len(EXPECTED_PROBES)} sondes Blackbox OK"

        details = []
        if missing:
            details.append(f"sondes absentes: {', '.join(sorted(missing))}")
        if failed:
            details.append(f"sondes en échec: {', '.join(sorted(failed))}")

        last_detail = "; ".join(details)
        time.sleep(5)

    return False, f"supervision incomplète ({last_detail})"


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
