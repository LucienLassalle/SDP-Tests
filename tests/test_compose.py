import pytest

pytestmark = pytest.mark.static


def test_compose_configuration(kics, sdp_src):
    # Trivy ne lit pas les fichiers compose : KICS vérifie secrets, ports, capabilities...
    compose = sdp_src / "docker-compose.yml"
    result = kics(compose, "--type", "DockerCompose", "--fail-on", "critical,high")
    report = result.stdout + result.stderr
    assert result.returncode == 0, f"KICS a trouvé des problèmes dans {compose} :\n{report}"

