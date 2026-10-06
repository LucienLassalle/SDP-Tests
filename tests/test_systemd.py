import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.static

# Score d'exposition max accepté (0 = très restreint, 10 = aucune restriction)
THRESHOLD = float(os.environ.get("SYSTEMD_SECURITY_THRESHOLD", "5"))


def test_services_are_hardened(sdp_src):
    if not shutil.which("systemd-analyze"):
        if os.environ.get("CI"):
            pytest.fail("systemd-analyze est absent de la CI")
        pytest.skip("systemd-analyze absent de cette machine")

    units = sorted(sdp_src.glob("deploy/*.service"))
    if not units:
        pytest.skip("aucun service systemd dans deploy/")

    failures = []
    for unit in units:
        # --threshold attend le score sur 100
        result = subprocess.run(
            ["systemd-analyze", "security", "--offline=true",
             f"--threshold={round(THRESHOLD * 10)}", str(unit)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            failures.append(f"--- {unit.name}\n{result.stdout}{result.stderr}")

    assert not failures, f"Services au-dessus du seuil {THRESHOLD} :\n" + "\n".join(failures)
