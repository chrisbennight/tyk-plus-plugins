#!/usr/bin/env bash
# Writes the SPDX SBOM that BuildKit attached to a release image, with this
# repository's own Go modules given the release version. The image build has
# no Git metadata, so it records their version as unknown.
#
# Usage: release/sbom.sh IMAGE@DIGEST VERSION > SBOM.spdx.json
set -euo pipefail

image=$1
version=$2
module=pkg:golang/github.com/chrisbennight/tyk-plus-plugins

# A multi-platform image lists one SBOM per platform; release images have one
# platform, so take the only entry.
docker buildx imagetools inspect "$image" --format '{{json .SBOM}}' | jq --arg module "$module" --arg version "$version" '
  (if has("SPDX") then .SPDX else ([.[]] | if length == 1 then .[0].SPDX else error("expected one platform, found \(length)") end) end)
  | .packages |= map(
      if any((.externalRefs // [])[]; .referenceType == "purl" and (.referenceLocator | (. == $module or startswith($module + "/") or startswith($module + "@"))))
      then
        .versionInfo = $version
        | .externalRefs |= map(
            if .referenceType == "purl" then .referenceLocator |= (
              (if contains("?") then "?" + (split("?")[1:] | join("?")) else "" end) as $qualifiers
              | (split("?")[0] | split("@")[0]) + "@" + $version + $qualifiers)
            else . end)
      else . end)'
