import pytest

pytestmark = pytest.mark.static

# Mêmes règles que l'ancien workflow : CRITICAL et HIGH sont bloquantes
COMMON_ARGS = ["--severity", "CRITICAL,HIGH", "--exit-code", "1", "--no-progress", "--skip-version-check"]


def assert_clean(result, target):
    report = result.stdout + result.stderr
    assert result.returncode == 0, f"Trivy a trouvé des problèmes sur {target} :\n{report}"


def test_filesystem(trivy, sdp_src):
    result = trivy("fs", *COMMON_ARGS, "--scanners", "vuln,secret,misconfig", str(sdp_src), mount=sdp_src)
    assert_clean(result, sdp_src)


def test_image(trivy, sdp_image):
    result = trivy("image", *COMMON_ARGS, sdp_image)
    assert_clean(result, sdp_image)
