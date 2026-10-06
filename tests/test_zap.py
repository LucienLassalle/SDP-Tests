import json
import os

import pytest

# Lancé avec les tests fonctionnels ; -m "functional and not fuzz" pour s'en passer en local
pytestmark = [pytest.mark.functional, pytest.mark.fuzz]

RISKS = {"low": 1, "medium": 2, "high": 3}
# Comme Trivy et KICS : seules les alertes High bloquent par défaut
FAIL_RISK = RISKS[os.environ.get("ZAP_FAIL_RISK", "high").lower()]
MAX_MINUTES = os.environ.get("ZAP_MAX_MINUTES", "10")


def describe(alert):
    lines = [f"[{alert['riskdesc']}] {alert['alert']} (règle {alert['pluginid']})"]
    for instance in alert["instances"][:5]:
        detail = f"    {instance['method']} {instance['uri']}"
        if instance.get("param"):
            detail += f" param={instance['param']}"
        if instance.get("attack"):
            detail += f" attaque={instance['attack']!r}"
        lines.append(detail)
    return "\n".join(lines)


def test_zap_full_scan(zap, base_url):
    # Exploration puis scan actif : ZAP injecte des charges (SQL, XSS, commandes...) dans chaque paramètre.
    # -I : ZAP ne décide pas de l'échec, le rapport JSON est filtré ci-dessous selon le risque.
    # Le certificat autosigné de SDP est accepté par ZAP sans configuration.
    result, reports = zap(
        "zap-full-scan.py", "-t", base_url, "-J", "report.json", "-r", "report.html", "-I", "-m", "2",
        "-z", f"-config scanner.maxScanDurationInMins={MAX_MINUTES}",
    )
    report_file = reports / "report.json"
    assert report_file.is_file(), f"ZAP n'a pas produit de rapport :\n{result.stdout}{result.stderr}"

    alerts = [alert for site in json.loads(report_file.read_text())["site"] for alert in site["alerts"]]
    failures = [alert for alert in alerts if int(alert["riskcode"]) >= FAIL_RISK]
    assert not failures, (
        f"ZAP a trouvé des failles (rapport complet : {reports / 'report.html'}) :\n"
        + "\n".join(describe(alert) for alert in failures)
    )
