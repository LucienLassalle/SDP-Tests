"""Linters sur le code de SDP : JavaScript, Dockerfile, scripts shell et workflows GitHub Actions."""
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.lint

LINT_DIR = Path(__file__).resolve().parent.parent / "lint"
# ESLint est installé par `npm ci` dans SDP-Tests, pas dans le PATH
NODE_BIN = LINT_DIR.parent / "node_modules" / ".bin"


def tool(name, install, path=None):
    """Chemin de l'outil, installé par requirements.txt ou package.json."""
    path = shutil.which(name, path=path)
    if not path:
        pytest.fail(f"{name} introuvable : {install}")
    return path


def files(sdp_src, pattern):
    """Fichiers de SDP correspondant au motif, hors node_modules."""
    found = sorted(p for p in sdp_src.glob(pattern) if "node_modules" not in p.parts)
    if not found:
        pytest.fail(f"aucun fichier {pattern} dans {sdp_src}")
    return [str(p.relative_to(sdp_src)) for p in found]


def assert_clean(cmd, sdp_src, what):
    result = subprocess.run(cmd, cwd=sdp_src, capture_output=True, text=True)
    if result.returncode != 0:
        # pytrace=False : seul le rapport de l'outil est affiché
        pytest.fail(f"{what} :\n{result.stdout}{result.stderr}", pytrace=False)


def test_javascript(sdp_src):
    eslint = tool("eslint", "lancer `npm ci` à la racine de SDP-Tests", path=str(NODE_BIN))
    assert_clean([eslint, "--config", str(LINT_DIR / "eslint.config.mjs"), "--max-warnings", "0",
                  *files(sdp_src, "**/*.js")], sdp_src, "ESLint a trouvé des problèmes")


def test_dockerfiles(sdp_src):
    hadolint = tool("hadolint", "installer requirements.txt (hadolint-bin)")
    assert_clean([hadolint, "--no-color", "--config", str(LINT_DIR / "hadolint.yaml"),
                  *files(sdp_src, "**/Dockerfile")], sdp_src, "hadolint a trouvé des problèmes")


def test_shell_scripts(sdp_src):
    shellcheck = tool("shellcheck", "installer requirements.txt (shellcheck-py)")
    assert_clean([shellcheck, *files(sdp_src, "**/*.sh")], sdp_src,
                 "ShellCheck a trouvé des problèmes")


def test_workflows(sdp_src):
    # actionlint lance aussi ShellCheck sur les blocs `run:` des workflows
    actionlint = tool("actionlint", "installer requirements.txt (actionlint-py)")
    tool("shellcheck", "installer requirements.txt (shellcheck-py)")
    assert_clean([actionlint, "-no-color", *files(sdp_src, ".github/workflows/*.yml")], sdp_src,
                 "actionlint a trouvé des problèmes dans les workflows")
