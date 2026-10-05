# SDP-Tests

## Analyse Trivy

Le workflow GitHub Actions `Trivy` analyse le dépôt et l’image Docker à chaque push, pull request et déclenchement manuel.

Il utilise les scans de vulnérabilités Trivy en mode filesystem (`scan-type: fs`) puis sur l’image Docker construite (`scan-type: image`).

Les résultats sont exportés au format SARIF et publiés comme artefact de workflow; les vulnérabilités critiques et hautes sont fatales pour bloquer la validation.
