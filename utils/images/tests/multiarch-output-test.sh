#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

images_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/multiarch-output-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM
mkdir "$test_root/bin"

cat >"$test_root/fixture.rb" <<'RUBY'
require "digest"
require "fileutils"
require "json"
require "tmpdir"

archive = ARGV.fetch(0)
Dir.mktmpdir("multiarch-output-fixture") do |root|
  blob_dir = File.join(root, "blobs", "sha256")
  FileUtils.mkdir_p(blob_dir)
  write_blob = lambda do |value|
    payload = JSON.generate(value)
    digest = Digest::SHA256.hexdigest(payload)
    File.binwrite(File.join(blob_dir, digest), payload)
    { "digest" => "sha256:#{digest}", "size" => payload.bytesize }
  end
  manifests = []
  attestations = []
  %w[amd64 arm64].each do |architecture|
    config = write_blob.call("config" => architecture)
    image = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "config" => config.merge("mediaType" => "application/vnd.oci.image.config.v1+json"), "layers" => [] }
    image_blob = write_blob.call(image)
    image_digest = image_blob.fetch("digest")
    manifests << image_blob.merge("mediaType" => image["mediaType"], "platform" => { "os" => "linux", "architecture" => architecture })
    [
      ["https://spdx.dev/Document", { "spdxVersion" => "SPDX-2.3", "packages" => [{ "name" => "fixture" }] }],
      ["https://slsa.dev/provenance/v1", { "buildDefinition" => { "buildType" => "https://example.invalid/build" }, "runDetails" => { "builder" => { "id" => "https://example.invalid/builder" } } }]
    ].each do |predicate_type, predicate|
      statement = { "_type" => "https://in-toto.io/Statement/v1", "subject" => [{ "name" => architecture, "digest" => { "sha256" => image_digest.delete_prefix("sha256:") } }], "predicateType" => predicate_type, "predicate" => predicate }
      layer = write_blob.call(statement).merge("mediaType" => "application/vnd.in-toto+json")
      attestation = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "layers" => [layer] }
      attestation_blob = write_blob.call(attestation)
      attestations << attestation_blob.merge("mediaType" => attestation["mediaType"], "annotations" => { "vnd.docker.reference.type" => "attestation-manifest", "vnd.docker.reference.digest" => image_digest })
    end
  end
  index = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.index.v1+json", "manifests" => manifests + attestations }
  File.write(File.join(root, "index.json"), JSON.generate(index))
  File.write(File.join(root, "oci-layout"), JSON.generate("imageLayoutVersion" => "1.0.0"))
  system("tar", "-cf", archive, "-C", root, "index.json", "oci-layout", "blobs", exception: true)
end
RUBY

cat >"$test_root/bin/docker" <<'SH'
#!/bin/sh
set -eu
[ "${1:-}" = buildx ] && [ "${2:-}" = build ] || exit 64
shift 2
output=
for argument in "$@"; do
  case "$argument" in
    type=oci,*) output=$argument ;;
  esac
done
[ -n "$output" ] || exit 64
dest=${output##*dest=}
printf '%s\n' "$*" >>"${FAKE_DOCKER_CALLS:?}"
/usr/bin/ruby "${FAKE_FIXTURE:?}" "$dest"
SH
chmod +x "$test_root/bin/docker"

cat >"$test_root/bin/ruby" <<'SH'
#!/bin/sh
set -eu
if [ "${1:-}" = tests/verify-oci-attestations.rb ]; then
  archive=${2:?archive path missing}
  before=$(/sbin/sha256sum "$archive" | awk '{print $1}')
  "${REAL_RUBY:?}" "$@"
  after=$(/sbin/sha256sum "$archive" | awk '{print $1}')
  [ "$before" = "$after" ] || { echo "strict verifier changed the exported archive" >&2; exit 1; }
  printf '%s\n' "$archive" >>"${FAKE_VERIFIER_CALLS:?}"
else
  exec "${REAL_RUBY:?}" "$@"
fi
SH
chmod +x "$test_root/bin/ruby"

: >"$test_root/docker.calls"
: >"$test_root/verifier.calls"
PATH="$test_root/bin:$PATH" \
FAKE_DOCKER_CALLS="$test_root/docker.calls" \
FAKE_VERIFIER_CALLS="$test_root/verifier.calls" \
FAKE_FIXTURE="$test_root/fixture.rb" \
REAL_RUBY=/usr/bin/ruby \
make -s -C "$images_root" multiarch

[ "$(wc -l <"$test_root/docker.calls" | tr -d ' ')" -eq 2 ] || { echo "multiarch target did not invoke both image exports" >&2; exit 1; }
[ "$(wc -l <"$test_root/verifier.calls" | tr -d ' ')" -eq 2 ] || { echo "multiarch target did not strictly verify both archives" >&2; exit 1; }
awk '/--output type=oci,oci-artifact=false,name=breakglass-local\/[^ ]*:validation,dest=/{count++} END { exit count == 2 ? 0 : 1 }' "$test_root/docker.calls" || { echo "multiarch export did not use the named non-artifact contract" >&2; exit 1; }
echo "multiarch output contract passed"
