#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

test_root=$(mktemp -d "${TMPDIR:-/tmp}/oci-attestation-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

# Build small, content-addressed OCI fixtures. The test exercises parsed
# archive behavior and its fail-closed path, rather than implementation text.
ruby - "$test_root" <<'RUBY'
require "digest"
require "fileutils"
require "json"

root = ARGV.fetch(0)
blob_dir = File.join(root, "blobs", "sha256")
FileUtils.mkdir_p(blob_dir)
descriptors = []
write_blob = lambda do |payload, media_type|
  digest = Digest::SHA256.hexdigest(payload)
  File.write(File.join(blob_dir, digest), payload)
  { "mediaType" => media_type, "digest" => "sha256:#{digest}", "size" => payload.bytesize }
end

%w[amd64 arm64].each do |architecture|
  config = write_blob.call("{}", "application/vnd.oci.image.config.v1+json")
  image = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "config" => config, "layers" => [] }
  image_payload = JSON.generate(image)
  image_digest = Digest::SHA256.hexdigest(image_payload)
  File.write(File.join(blob_dir, image_digest), image_payload)
  descriptors << { "mediaType" => image["mediaType"], "digest" => "sha256:#{image_digest}", "size" => image_payload.bytesize, "platform" => { "os" => "linux", "architecture" => architecture } }

  %w[sbom provenance].each do |kind|
    statement = if kind == "sbom"
                  { "_type" => "https://in-toto.io/Statement/v1", "predicateType" => "https://spdx.dev/Document", "predicate" => { "spdxVersion" => "SPDX-2.3" } }
                else
                  { "_type" => "https://in-toto.io/Statement/v1", "predicateType" => "https://slsa.dev/provenance/v1", "predicate" => {} }
                end
    layer = write_blob.call(JSON.generate(statement), "application/vnd.in-toto+json")
    attestation = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "layers" => [layer], "subject" => { "digest" => "sha256:#{image_digest}" } }
    attestation_payload = JSON.generate(attestation)
    attestation_digest = Digest::SHA256.hexdigest(attestation_payload)
    File.write(File.join(blob_dir, attestation_digest), attestation_payload)
    descriptors << { "mediaType" => attestation["mediaType"], "digest" => "sha256:#{attestation_digest}", "size" => attestation_payload.bytesize, "annotations" => { "vnd.docker.reference.type" => "attestation-manifest", "vnd.docker.reference.digest" => "sha256:#{image_digest}" } }
  end
end

nested = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.index.v1+json", "manifests" => descriptors }
nested_payload = JSON.generate(nested)
nested_digest = Digest::SHA256.hexdigest(nested_payload)
File.write(File.join(blob_dir, nested_digest), nested_payload)
root_index = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.index.v1+json", "manifests" => [{ "mediaType" => nested["mediaType"], "digest" => "sha256:#{nested_digest}", "size" => nested_payload.bytesize }] }
File.write(File.join(root, "index.json"), JSON.generate(root_index))
nested["manifests"].reject! { |descriptor| descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest" }
bad_nested_payload = JSON.generate(nested)
bad_nested_digest = Digest::SHA256.hexdigest(bad_nested_payload)
File.write(File.join(blob_dir, bad_nested_digest), bad_nested_payload)
bad_root_index = root_index.merge("manifests" => [{ "mediaType" => nested["mediaType"], "digest" => "sha256:#{bad_nested_digest}", "size" => bad_nested_payload.bytesize }])
File.write(File.join(root, "bad-index.json"), JSON.generate(bad_root_index))
RUBY

(cd "$test_root" && tar -cf "$test_root/good.tar" index.json blobs)
mkdir "$test_root/bad"
cp "$test_root/bad-index.json" "$test_root/bad/index.json"
cp -R "$test_root/blobs" "$test_root/bad/"
(cd "$test_root/bad" && tar -cf "$test_root/bad.tar" index.json blobs)

ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/good.tar" >/dev/null
if ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/bad.tar" >/dev/null 2>&1; then
    echo "archive without attestations was accepted" >&2
    exit 1
fi

echo "OCI attestation inspection behavior passed"
