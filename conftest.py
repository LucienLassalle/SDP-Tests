import os
import shutil
import subprocess
from pathlib import Path

import pytest

# Images officielles épinglées par digest, utilisées si l'outil n'est pas installé
TRIVY_IMAGE = (
    "aquasec/trivy:0.74.0"
    "@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
)
KICS_IMAGE = (
    "checkmarx/kics:v2.1.20"
    "@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602"
)
TRIVY_CACHE = Path(os.environ.get("TRIVY_CACHE_DIR", Path.home() / ".cache" / "trivy"))
# docker ou podman
CONTAINER_ENGINE = os.environ.get("CONTAINER_ENGINE", "docker")
DOCKER_SOCKET = Path("/var/run/docker.sock")


def container(image, *args, volumes=()):
    """Commande pour lancer un outil dans un conteneur jetable."""
    cmd = [CONTAINER_ENGINE, "run", "--rm", "--security-opt", "label=disable"]
    for volume in volumes:
        cmd += ["-v", volume]
    return [*cmd, image, *args]


@pytest.fixture(scope="session")
def sdp_src():
    """Chemin du code source de SDP à analyser."""
    path = Path(os.environ.get("SDP_SRC", "../SDP")).resolve()
    if not (path / "Dockerfile").is_file():
        pytest.fail(f"SDP_SRC={path} ne contient pas le code de SDP")
    return path


@pytest.fixture(scope="session")
def sdp_image():
    """Image Docker de SDP déjà construite."""
    image = os.environ.get("SDP_IMAGE")
    if not image:
        pytest.fail("SDP_IMAGE doit indiquer l'image Docker de SDP à analyser")
    return image


@pytest.fixture(scope="session")
def trivy():
    """Lance trivy (binaire local ou image Docker) et renvoie le résultat."""
    TRIVY_CACHE.mkdir(parents=True, exist_ok=True)

    def run(*args, mount=None):
        if shutil.which("trivy"):
            cmd = ["trivy", "--cache-dir", str(TRIVY_CACHE), *args]
        else:
            volumes = [f"{TRIVY_CACHE}:/root/.cache/trivy"]
            if DOCKER_SOCKET.exists():
                volumes.append(f"{DOCKER_SOCKET}:{DOCKER_SOCKET}")
            if mount:
                volumes.append(f"{mount}:{mount}:ro")
            cmd = container(TRIVY_IMAGE, *args, volumes=volumes)
        return subprocess.run(cmd, capture_output=True, text=True)

    return run


@pytest.fixture(scope="session")
def kics():
    """Lance kics (binaire local ou image Docker) et renvoie le résultat."""

    def run(path, *args):
        common = ["scan", "--no-progress", "--no-color", "--disable-full-descriptions", *args]
        if shutil.which("kics"):
            cmd = ["kics", *common, "-p", str(path)]
        else:
            cmd = container(KICS_IMAGE, *common, "-p", str(path),
                            volumes=[f"{path.parent}:{path.parent}:ro"])
        return subprocess.run(cmd, capture_output=True, text=True)

    return run
