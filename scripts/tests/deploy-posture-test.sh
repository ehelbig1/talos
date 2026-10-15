#!/usr/bin/env bash
# The repository's own deployment artefacts pass scripts/check-deploy-posture.py
# (its --self-test runs separately, discovered by run-script-tests.sh). This is
# the tree check, so `make test-scripts` fails when an edit to the compose
# file, the chart, the nginx configs or a workflow undoes a reviewed posture.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$HERE/../check-deploy-posture.py" "$HERE/../.."
