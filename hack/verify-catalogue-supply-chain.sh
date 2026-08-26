#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Verify the immutable publication contract for the standalone catalogue:
# utility images must be multi-arch, digest-pinned, keylessly signed, and
# carry SPDX SBOM plus SLSA provenance attestations. The chart itself is an
# OCI artifact and is verified by digest with the same attestations.

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: verify-catalogue-supply-chain.sh --images-file FILE --chart REF

REF is an OCI reference without the oci:// scheme and must include
@sha256:<64 lowercase hexadecimal characters>. IMAGE_FILE contains one such
image reference per line; blank lines and lines beginning with # are ignored.
EOF
}

die() {
  printf 'catalogue supply-chain verification: %s\n' "$*" >&2
  exit 1
}

IMAGES_FILE=''
CHART_REF=''
while (($# > 0)); do
  case "$1" in
    --images-file)
      (($# >= 2)) || die "--images-file requires a path"
      IMAGES_FILE="$2"
      shift 2
      ;;
    --chart)
      (($# >= 2)) || die "--chart requires an OCI digest reference"
      CHART_REF="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$IMAGES_FILE" && -f "$IMAGES_FILE" ]] || die "image reference file is missing"
[[ "$CHART_REF" != oci://* ]] || die "chart reference must omit the oci:// scheme"
[[ "$CHART_REF" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]] || \
  die "chart reference must be an immutable sha256 digest"
command -v cosign >/dev/null 2>&1 || die "cosign is required"
command -v docker >/dev/null 2>&1 || die "docker is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

IDENTITY_REGEXP="${SUPPLY_CHAIN_IDENTITY_REGEXP:-https://github.com/telekom/k8s-breakglass/.github/workflows/release.yml@refs/tags/v[0-9].*}"
OIDC_ISSUER="${SUPPLY_CHAIN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

verify_attestations() {
  local subject="$1" label="$2"
  printf 'Verifying %s signature: %s\n' "$label" "$subject"
  cosign verify "$subject" \
    --certificate-identity-regexp="$IDENTITY_REGEXP" \
    --certificate-oidc-issuer="$OIDC_ISSUER" >/dev/null
  printf 'Verifying %s SPDX SBOM attestation\n' "$label"
  cosign verify-attestation "$subject" --type spdxjson \
    --certificate-identity-regexp="$IDENTITY_REGEXP" \
    --certificate-oidc-issuer="$OIDC_ISSUER" >/dev/null
  printf 'Verifying %s SLSA provenance attestation\n' "$label"
  cosign verify-attestation "$subject" --type slsaprovenance \
    --certificate-identity-regexp="$IDENTITY_REGEXP" \
    --certificate-oidc-issuer="$OIDC_ISSUER" >/dev/null
}

verify_multiarch() {
  local subject="$1" raw
  raw="$(docker buildx imagetools inspect --raw "$subject")" || \
    die "could not inspect image manifest: $subject"
  jq -e '
    (.manifests | type == "array" and length >= 2) and
    ([.manifests[]?.platform | "\(.os)/\(.architecture)"] | index("linux/amd64")) and
    ([.manifests[]?.platform | "\(.os)/\(.architecture)"] | index("linux/arm64"))
  ' <<<"$raw" >/dev/null || die "image is not a linux amd64/arm64 multi-arch manifest: $subject"
}

image_count=0
while IFS= read -r image_ref || [[ -n "$image_ref" ]]; do
  [[ -z "$image_ref" || "$image_ref" == \#* ]] && continue
  [[ "$image_ref" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]] || \
    die "utility image is not an immutable sha256 digest: $image_ref"
  verify_multiarch "$image_ref"
  verify_attestations "$image_ref" "utility image"
  image_count=$((image_count + 1))
done < "$IMAGES_FILE"
((image_count > 0)) || die "no utility image references were supplied"

verify_attestations "$CHART_REF" "catalogue chart"
printf 'Catalogue supply-chain verification passed (%d utility images, chart %s)\n' \
  "$image_count" "$CHART_REF"
