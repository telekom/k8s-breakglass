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
attestation_descriptors = {}
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
                  { "_type" => "https://in-toto.io/Statement/v1", "subject" => [{ "name" => "ghcr.io/example/utility", "digest" => { "sha256" => image_digest } }], "predicateType" => "https://spdx.dev/Document", "predicate" => { "spdxVersion" => "SPDX-2.3", "packages" => [{ "name" => "example" }] } }
                else
                  { "_type" => "https://in-toto.io/Statement/v1", "subject" => [{ "name" => "ghcr.io/example/utility", "digest" => { "sha256" => image_digest } }], "predicateType" => "https://slsa.dev/provenance/v1", "predicate" => { "buildDefinition" => { "buildType" => "https://example.invalid/build" }, "runDetails" => { "builder" => { "id" => "https://example.invalid/builder" } } } }
                end
    layer = write_blob.call(JSON.generate(statement), "application/vnd.in-toto+json")
    attestation = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "layers" => [layer], "subject" => { "digest" => "sha256:#{image_digest}" } }
    attestation_payload = JSON.generate(attestation)
    attestation_digest = Digest::SHA256.hexdigest(attestation_payload)
    File.write(File.join(blob_dir, attestation_digest), attestation_payload)
    descriptor = { "mediaType" => attestation["mediaType"], "digest" => "sha256:#{attestation_digest}", "size" => attestation_payload.bytesize, "annotations" => { "vnd.docker.reference.type" => "attestation-manifest", "vnd.docker.reference.digest" => "sha256:#{image_digest}" } }
    descriptors << descriptor
    attestation_descriptors[[architecture, kind]] = descriptor
  end
end

write_index = lambda do |filename, selected_descriptors|
  nested = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.index.v1+json", "manifests" => selected_descriptors }
  nested_payload = JSON.generate(nested)
  nested_digest = Digest::SHA256.hexdigest(nested_payload)
  File.write(File.join(blob_dir, nested_digest), nested_payload)
  root_index = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.index.v1+json", "manifests" => [{ "mediaType" => nested["mediaType"], "digest" => "sha256:#{nested_digest}", "size" => nested_payload.bytesize }] }
  File.write(File.join(root, filename), JSON.generate(root_index))
end

# Add a content-addressed attestation whose in-toto predicate is an empty
# placeholder. The verifier must reject it even though all OCI digests bind.
provenance_descriptor = attestation_descriptors.fetch(["amd64", "provenance"])
provenance_manifest = JSON.parse(File.read(File.join(blob_dir, provenance_descriptor["digest"].delete_prefix("sha256:"))))
empty_statement = { "_type" => "https://in-toto.io/Statement/v1", "subject" => [{ "digest" => { "sha256" => descriptors.first["digest"].delete_prefix("sha256:") } }], "predicateType" => "https://slsa.dev/provenance/v1", "predicate" => {} }
empty_layer = write_blob.call(JSON.generate(empty_statement), "application/vnd.in-toto+json")
provenance_manifest["layers"] = [empty_layer]
empty_manifest_payload = JSON.generate(provenance_manifest)
empty_manifest_digest = Digest::SHA256.hexdigest(empty_manifest_payload)
File.write(File.join(blob_dir, empty_manifest_digest), empty_manifest_payload)
empty_descriptor = provenance_descriptor.merge("digest" => "sha256:#{empty_manifest_digest}")
empty_descriptors = descriptors.map { |descriptor| descriptor["digest"] == provenance_descriptor["digest"] ? empty_descriptor : descriptor }

write_index.call("index.json", descriptors)
write_index.call("bad-index.json", descriptors.reject { |descriptor| descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest" })
write_index.call("missing-sbom-index.json", descriptors.reject { |descriptor| descriptor["digest"] == attestation_descriptors.fetch(["amd64", "sbom"])["digest"] })
write_index.call("missing-provenance-index.json", descriptors.reject { |descriptor| descriptor["digest"] == attestation_descriptors.fetch(["arm64", "provenance"])["digest"] })
write_index.call("empty-provenance-index.json", empty_descriptors)
RUBY

(cd "$test_root" && tar -cf "$test_root/good.tar" index.json blobs)
for variant in bad missing-sbom missing-provenance empty-provenance; do
    mkdir "$test_root/$variant"
    cp "$test_root/$variant-index.json" "$test_root/$variant/index.json"
    cp -R "$test_root/blobs" "$test_root/$variant/"
    (cd "$test_root/$variant" && tar -cf "$test_root/$variant.tar" index.json blobs)
done

ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/good.tar" >/dev/null
for variant in bad missing-sbom missing-provenance empty-provenance; do
    if ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/$variant.tar" >/dev/null 2>&1; then
        echo "invalid $variant archive was accepted" >&2
        exit 1
    fi
done

echo "OCI attestation inspection behavior passed"
