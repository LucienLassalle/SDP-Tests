import pytest

pytestmark = pytest.mark.static


def test_compose_configuration(kics, sdp_src):
    # Trivy ne lit pas les fichiers compose : KICS vérifie secrets, ports, capabilities...
    compose = sdp_src / "docker-compose.yml"
    result = kics(compose, "--type", "DockerCompose", "--fail-on", "critical,high")
    report = result.stdout + result.stderr
    assert result.returncode == 0, f"KICS a trouvé des problèmes dans {compose} :\n{report}"


def test_compose_images(trivy, compose_images, sdp_image):
    # L'image de SDP est déjà analysée par test_trivy.py::test_image
    images = [image for image in compose_images if image != sdp_image]

    failures = []
    for image in images:
        result = trivy("image", "--severity", "CRITICAL,HIGH", "--exit-code", "1",
                       "--no-progress", "--skip-version-check", image)
        if result.returncode != 0:
            failures.append(f"--- {image}\n{result.stdout}{result.stderr}")

    assert not failures, "Trivy a trouvé des problèmes dans les images du compose :\n" + "\n".join(failures)
