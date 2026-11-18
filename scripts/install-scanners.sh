#!/usr/bin/env bash
# Install the tools collectors call, pinned by version and SHA-256: the scanners,
# and gh, which verifies GitHub's attestations.
#
#   scripts/install-scanners.sh <bin directory> [trufflehog] [grype] [gh]
#
# Downloads the official linux/amd64 release archives, refuses any archive
# whose SHA-256 differs from the one pinned here, and puts the tools named, or
# both scanners, in <bin directory>. Needs curl, sha256sum and tar; no root. On
# GitHub Actions the directory is also added to PATH for the steps that follow.
#
# The versions must match tests/scanners/versions.json, which records the output
# the tests replay; a test fails if they drift. To move to a new version, change
# it here with the checksum from the release's checksums file, run
# tests/scanners/record.py with that version, and fix what the tests report.
set -euo pipefail

TRUFFLEHOG_VERSION="3.99.9"
TRUFFLEHOG_SHA256="12050095c8063bf4d34f9f6cbce6ba9fa8d0deea9d503d0570364feba093658e"
GRYPE_VERSION="0.121.0"
GRYPE_SHA256="64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519"
GH_VERSION="2.102.0"
GH_SHA256="bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386"

bin="${1:?usage: $0 <bin directory> [trufflehog] [grype] [gh]}"
shift
if [ $# -eq 0 ]; then set -- trufflehog grype; fi
for tool in "$@"; do
  case "$tool" in
    trufflehog | grype | gh) ;;
    *) echo "unknown tool '$tool': trufflehog, grype or gh" >&2; exit 1 ;;
  esac
done
if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
  echo "only linux/amd64 is pinned here, not $(uname -s)-$(uname -m)" >&2
  exit 1
fi
mkdir -p "$bin"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# fetch <name> <url> <sha256> [path of the binary in the archive, default <name>]
fetch() {
  local name="$1" url="$2" sha256="$3" member="${4:-$1}"
  curl -fsSL --retry 3 -o "$scratch/$name.tar.gz" "$url"
  if ! echo "$sha256  $scratch/$name.tar.gz" | sha256sum --check --status; then
    echo "$name: the archive from $url does not have the pinned SHA-256" >&2
    exit 1
  fi
  tar -xzf "$scratch/$name.tar.gz" -C "$scratch" "$member"
  mv "$scratch/$member" "$bin/$name"
  chmod 755 "$bin/$name"
}

for tool in "$@"; do
  case "$tool" in
    trufflehog)
      fetch trufflehog \
        "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
        "$TRUFFLEHOG_SHA256"
      "$bin/trufflehog" --version ;;
    grype)
      fetch grype \
        "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
        "$GRYPE_SHA256"
      "$bin/grype" version | sed -n '1,2p' ;;
    gh)
      fetch gh \
        "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" \
        "$GH_SHA256" "gh_${GH_VERSION}_linux_amd64/bin/gh"
      "$bin/gh" --version | sed -n 1p ;;
  esac
done

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$bin" >>"$GITHUB_PATH"
fi
