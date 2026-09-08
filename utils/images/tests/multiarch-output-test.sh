#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

images_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
recipe=$(make -s -C "$images_root" -n multiarch)
case "$recipe" in
  *'--output "type=oci,oci-artifact=false,name=breakglass-local/$image:validation,dest=$archive" "$image";'*) ;;
  *)
    echo "multiarch target must use a named non-artifact OCI export" >&2
    exit 1
    ;;
esac
case "$recipe" in
  *normalize-oci-attestations.rb*)
    echo "multiarch target must verify the untouched export" >&2
    exit 1
    ;;
esac
case "$recipe" in
  *'ruby tests/verify-oci-attestations.rb "$archive";'*) ;;
  *)
    echo "multiarch target must strictly verify each exported archive" >&2
    exit 1
    ;;
esac
echo "multiarch output contract passed"
