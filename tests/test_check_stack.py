import io
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from scripts import check_stack as app


class TestRun(unittest.TestCase):

    @patch.object(app.subprocess, "run")
    def test_run_success(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "sortie"
        mock_run.return_value.stderr = "information"

        code, output = app.run(["echo", "test"])

        self.assertEqual(code, 0)
        self.assertEqual(output, "sortieinformation")

    @patch.object(app.subprocess, "run")
    def test_run_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(["sleep"], 2)

        code, output = app.run(["sleep", "10"], timeout=2)

        self.assertEqual(code, 124)
        self.assertEqual(output, "délai dépassé")

    @patch.object(app, "run", return_value=(0, "OK"))
    def test_docker_exec(self, mock_run):
        result = app.docker_exec("router-fw", "nft list ruleset", 8)

        self.assertEqual(result, (0, "OK"))
        mock_run.assert_called_once_with(
            ["docker", "exec", "router-fw", "sh", "-c", "nft list ruleset"],
            8
        )


class TestHttpStatus(unittest.TestCase):

    @patch.object(app.urllib.request, "urlopen")
    @patch.object(app.ssl, "create_default_context")
    def test_http_success(self, mock_context, mock_urlopen):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_urlopen.return_value = Response()

        status = app.http_status("https://example.test")

        self.assertEqual(status, 200)
        mock_context.return_value.check_hostname = False
        mock_context.return_value.verify_mode = app.ssl.CERT_NONE

    @patch.object(
        app.urllib.request,
        "urlopen",
        side_effect=OSError("connexion impossible")
    )
    def test_http_error(self, mock_urlopen):
        self.assertEqual(app.http_status("http://example.test"), 0)


class TestConnectivity(unittest.TestCase):

    @patch.object(app, "docker_exec", return_value=(0, "policy drop"))
    def test_firewall_loaded(self, mock_docker):
        self.assertTrue(app.test_firewall_loaded()[0])

    @patch.object(app, "docker_exec", return_value=(1, "erreur nftables"))
    def test_firewall_error(self, mock_docker):
        self.assertFalse(app.test_firewall_loaded()[0])

    @patch.object(app, "http_status", return_value=200)
    def test_dnat_http_success(self, mock_http):
        self.assertTrue(app.test_dnat_http()[0])

    @patch.object(app, "http_status", return_value=500)
    def test_dnat_http_error(self, mock_http):
        self.assertFalse(app.test_dnat_http()[0])

    @patch.object(app, "http_status", return_value=200)
    def test_dnat_https_success(self, mock_http):
        self.assertTrue(app.test_dnat_https()[0])

    @patch.object(app, "http_status", return_value=0)
    def test_dnat_https_error(self, mock_http):
        self.assertFalse(app.test_dnat_https()[0])

    @patch.object(app, "docker_exec", return_value=(0, app.WEB_IP))
    def test_dns_success(self, mock_docker):
        self.assertTrue(app.test_dns_resolution()[0])

    @patch.object(app, "docker_exec", return_value=(1, "DNS indisponible"))
    def test_dns_error(self, mock_docker):
        self.assertFalse(app.test_dns_resolution()[0])

    @patch.object(app, "docker_exec", return_value=(0, "200"))
    def test_lan_to_web_success(self, mock_docker):
        self.assertTrue(app.test_lan_to_web()[0])

    @patch.object(app, "docker_exec", return_value=(1, "000"))
    def test_lan_to_web_error(self, mock_docker):
        self.assertFalse(app.test_lan_to_web()[0])

    @patch.object(app, "docker_exec", side_effect=[(0, ""), (1, "bloqué")])
    def test_dmz_to_lan_blocked(self, mock_docker):
        self.assertTrue(app.test_dmz_to_lan_blocked()[0])

    @patch.object(app, "docker_exec", side_effect=[(0, ""), (0, "accessible")])
    def test_dmz_to_lan_not_blocked(self, mock_docker):
        self.assertFalse(app.test_dmz_to_lan_blocked()[0])

    @patch.object(app, "docker_exec", side_effect=[(0, ""), (1, "bloqué")])
    def test_lan_to_mgmt_blocked(self, mock_docker):
        self.assertTrue(app.test_lan_to_mgmt_blocked()[0])

    @patch.object(app, "docker_exec", side_effect=[(1, ""), (1, "bloqué")])
    def test_lan_to_mgmt_control_failure(self, mock_docker):
        self.assertFalse(app.test_lan_to_mgmt_blocked()[0])


class TestMonitoring(unittest.TestCase):

    @patch.object(app, "run", return_value=(1, "absent"))
    def test_prometheus_absent(self, mock_run):
        result, detail = app.test_monitoring()

        self.assertIsNone(result)
        self.assertEqual(detail, "supervision non déployée")

    @patch.object(app, "run", return_value=(0, "présent"))
    @patch.object(app, "docker_exec")
    def test_prometheus_success(self, mock_docker, mock_run):
        payload = {
            "status": "success",
            "data": {
                "result": [
                    {"value": [0, "1"]},
                    {"value": [0, "1"]},
                    {"value": [0, "1"]}
                ]
            }
        }
        mock_docker.return_value = (0, json.dumps(payload))

        result, detail = app.test_monitoring()

        self.assertTrue(result)
        self.assertEqual(detail, "3 sondes OK")

    @patch.object(app, "run", return_value=(0, "présent"))
    @patch.object(app, "docker_exec", return_value=(1, "connexion refusée"))
    def test_prometheus_connection_error(self, mock_docker, mock_run):
        self.assertFalse(app.test_monitoring()[0])

    @patch.object(app, "run", return_value=(0, "présent"))
    @patch.object(app, "docker_exec", return_value=(0, "JSON invalide"))
    def test_prometheus_invalid_json(self, mock_docker, mock_run):
        self.assertFalse(app.test_monitoring()[0])

    @patch.object(app, "run", return_value=(0, "présent"))
    @patch.object(app, "docker_exec")
    def test_prometheus_api_error(self, mock_docker, mock_run):
        mock_docker.return_value = (
            0,
            json.dumps({"status": "error", "data": {"result": []}})
        )
        self.assertFalse(app.test_monitoring()[0])

    @patch.object(app.time, "sleep")
    @patch.object(app.time, "time", side_effect=[0, 0, 61])
    @patch.object(app, "run", return_value=(0, "présent"))
    @patch.object(app, "docker_exec")
    def test_prometheus_failed_probe(
        self, mock_docker, mock_run, mock_time, mock_sleep
    ):
        payload = {
            "status": "success",
            "data": {"result": [{"value": [0, "0"]}]}
        }
        mock_docker.return_value = (0, json.dumps(payload))

        result, detail = app.test_monitoring()

        self.assertFalse(result)
        self.assertIn("1/1 sonde(s) en échec", detail)

    @patch.object(app.time, "sleep")
    @patch.object(app.time, "time", side_effect=[0, 0, 61])
    @patch.object(app, "run", return_value=(0, "présent"))
    @patch.object(app, "docker_exec")
    def test_prometheus_empty_results(
        self, mock_docker, mock_run, mock_time, mock_sleep
    ):
        payload = {"status": "success", "data": {"result": []}}
        mock_docker.return_value = (0, json.dumps(payload))

        result, detail = app.test_monitoring()

        self.assertFalse(result)
        self.assertIn("aucune sonde disponible", detail)


class TestMain(unittest.TestCase):

    def test_main_counts_success_failure_and_skip(self):
        def success():
            """Test réussi."""
            return True, "OK"

        def failure():
            """Test échoué."""
            return False, "Erreur"

        def skipped():
            """Test ignoré."""
            return None, "Absent"

        with patch.object(app, "TESTS", [success, failure, skipped]):
            output = io.StringIO()
            with redirect_stdout(output):
                result = app.main()

        self.assertEqual(result, 1)
        self.assertIn("1 échec(s)", output.getvalue())
        self.assertIn("SKIP", output.getvalue())


if __name__ == "__main__":
    unittest.main()
