#!/usr/bin/env bash
# Scans an SPDX SBOM with Grype against a fresh vulnerability database, and
# fails on any critical vulnerability, or any high one that has a fix, that
# release/vex.json does not cover. It writes Grype's full JSON report and
# prints a summary table. It exits with status 3 when the gate fails, and
# with another nonzero status when the scan itself fails.
#
# Usage: release/scan.sh SBOM.spdx.json REPORT.json
set -euo pipefail

sbom=$1
report=$2
grype=anchore/grype:v0.122.1@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c
vex=$(cd "$(dirname "$0")" && pwd)/vex.json
sbom_dir=$(cd "$(dirname "$sbom")" && pwd)

run_args=()
if jq -e '.statements | length > 0' "$vex" >/dev/null; then
  run_args=(-v "$vex:/vex.json:ro" "$grype" --vex /vex.json)
else
  run_args=("$grype")
fi
docker run --rm -v "$sbom_dir:/sbom:ro" "${run_args[@]}" \
  "sbom:/sbom/$(basename "$sbom")" -o json > "$report"

jq -r '
  ["SEVERITY", "ID", "PACKAGE", "VERSION", "FIX"],
  (.matches | sort_by(.vulnerability.severity, .vulnerability.id)[]
    | [.vulnerability.severity, .vulnerability.id, .artifact.name, .artifact.version,
       (if .vulnerability.fix.state == "fixed" then (.vulnerability.fix.versions | join(", ")) else .vulnerability.fix.state end)])
  | @tsv' "$report" | column -t -s $'\t'

blocking=$(jq '[.matches[] | select(.vulnerability.severity == "Critical"
  or (.vulnerability.severity == "High" and .vulnerability.fix.state == "fixed"))] | length' "$report")
if [ "$blocking" -ne 0 ]; then
  echo "$sbom: $blocking critical, or high with a fix, not covered by release/vex.json" >&2
  exit 3
fi
echo "$sbom: no critical vulnerabilities, and no high ones with a fix"
