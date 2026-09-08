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
require "stringio"
require "zlib"

root = ARGV.fetch(0)
blob_dir = File.join(root, "blobs", "sha256")
FileUtils.mkdir_p(blob_dir)
descriptors = []
attestation_descriptors = {}
write_blob = lambda do |payload, media_type, compressed = false|
  stored_payload = if compressed
                     output = StringIO.new
                     Zlib::GzipWriter.wrap(output) { |gzip| gzip.write(payload) }
                     output.string
                   else
                     payload
                   end
  digest = Digest::SHA256.hexdigest(stored_payload)
  File.write(File.join(blob_dir, digest), stored_payload)
  { "mediaType" => media_type, "digest" => "sha256:#{digest}", "size" => stored_payload.bytesize }
end

%w[amd64 arm64].each do |architecture|
  config = write_blob.call(JSON.generate("architecture" => architecture), "application/vnd.oci.image.config.v1+json")
  image = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "config" => config, "layers" => [] }
  image_payload = JSON.generate(image)
  image_digest = Digest::SHA256.hexdigest(image_payload)
  File.write(File.join(blob_dir, image_digest), image_payload)
  File.write(File.join(root, "#{architecture}-image-digest"), image_digest)
  descriptors << { "mediaType" => image["mediaType"], "digest" => "sha256:#{image_digest}", "size" => image_payload.bytesize, "platform" => { "os" => "linux", "architecture" => architecture } }

  %w[sbom provenance].each do |kind|
    statement = if kind == "sbom"
                  { "_type" => (architecture == "arm64" ? "https://in-toto.io/Statement/v0.1" : "https://in-toto.io/Statement/v1"), "subject" => [{ "name" => "ghcr.io/example/utility", "digest" => { "sha256" => image_digest } }], "predicateType" => "https://spdx.dev/Document", "predicate" => { "spdxVersion" => "SPDX-2.3", "packages" => [{ "name" => "example" }] } }
                else
                  subject = [{ "name" => "ghcr.io/example/utility", "digest" => { "sha256" => image_digest } }]
                  predicate_type = architecture == "arm64" ? "https://slsa.dev/provenance/v0.2" : "https://slsa.dev/provenance/v1"
                  predicate = if architecture == "arm64"
                                { "builder" => { "id" => "https://example.invalid/builder" }, "buildType" => "https://example.invalid/build" }
                              else
                                { "buildDefinition" => { "buildType" => "https://example.invalid/build" }, "runDetails" => { "builder" => { "id" => "https://example.invalid/builder" } } }
                              end
                  { "_type" => (architecture == "arm64" ? "https://in-toto.io/Statement/v0.1" : "https://in-toto.io/Statement/v1"), "subject" => subject, "predicateType" => predicate_type, "predicate" => predicate }
                end
    layer = write_blob.call(JSON.generate(statement), "application/vnd.in-toto+json", kind == "sbom")
    # BuildKit links index-style attestations through the descriptor annotation;
    # the attestation manifest itself need not carry an OCI subject field.
    attestation = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "layers" => [layer] }
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

arm64_provenance_descriptor = attestation_descriptors.fetch(["arm64", "provenance"])
arm64_provenance_manifest = JSON.parse(File.read(File.join(blob_dir, arm64_provenance_descriptor["digest"].delete_prefix("sha256:"))))
malformed_statement = { "_type" => "https://in-toto.io/Statement/v0.1", "subject" => [], "predicateType" => "https://slsa.dev/provenance/v0.2", "predicate" => { "builder" => { "id" => "" } } }
malformed_layer = write_blob.call(JSON.generate(malformed_statement), "application/vnd.in-toto+json")
arm64_provenance_manifest["layers"] = [malformed_layer]
malformed_manifest_payload = JSON.generate(arm64_provenance_manifest)
malformed_manifest_digest = Digest::SHA256.hexdigest(malformed_manifest_payload)
File.write(File.join(blob_dir, malformed_manifest_digest), malformed_manifest_payload)
malformed_descriptor = arm64_provenance_descriptor.merge("digest" => "sha256:#{malformed_manifest_digest}")
malformed_descriptors = descriptors.map { |descriptor| descriptor["digest"] == arm64_provenance_descriptor["digest"] ? malformed_descriptor : descriptor }

amd64_image = descriptors.find { |descriptor| descriptor.dig("platform", "architecture") == "amd64" }
arm64_image = descriptors.find { |descriptor| descriptor.dig("platform", "architecture") == "arm64" }
mismatched_reference_descriptors = descriptors.map do |descriptor|
  if descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest" && descriptor.dig("annotations", "vnd.docker.reference.digest") == amd64_image["digest"]
    descriptor.merge("annotations" => descriptor["annotations"].merge("vnd.docker.reference.digest" => arm64_image["digest"]))
  else
    descriptor
  end
end
missing_reference_descriptors = descriptors.map do |descriptor|
  if descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest" && descriptor.dig("annotations", "vnd.docker.reference.digest") == amd64_image["digest"]
    descriptor.merge("annotations" => descriptor["annotations"].reject { |key, _| key == "vnd.docker.reference.digest" })
  else
    descriptor
  end
end

write_index.call("index.json", descriptors)
write_index.call("bad-index.json", descriptors.reject { |descriptor| descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest" })
write_index.call("missing-sbom-index.json", descriptors.reject { |descriptor| descriptor["digest"] == attestation_descriptors.fetch(["amd64", "sbom"])["digest"] })
write_index.call("missing-provenance-index.json", descriptors.reject { |descriptor| descriptor["digest"] == attestation_descriptors.fetch(["arm64", "provenance"])["digest"] })
write_index.call("empty-provenance-index.json", empty_descriptors)
bad_media_type_descriptors = descriptors.map do |descriptor|
  if descriptor.dig("platform", "architecture") == "amd64"
    descriptor.merge("mediaType" => "application/vnd.oci.image.config.v1+json")
  else
    descriptor
  end
end
write_index.call("bad-image-media-type-index.json", bad_media_type_descriptors)
malformed_image_payload = JSON.generate("schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json")
malformed_image_digest = Digest::SHA256.hexdigest(malformed_image_payload)
File.write(File.join(blob_dir, malformed_image_digest), malformed_image_payload)
malformed_image_descriptors = descriptors.map do |descriptor|
  if descriptor.dig("platform", "architecture") == "amd64"
    descriptor.merge("digest" => "sha256:#{malformed_image_digest}", "size" => malformed_image_payload.bytesize)
  else
    descriptor
  end
end
write_index.call("malformed-image-index.json", malformed_image_descriptors)
write_index.call("malformed-v02-index.json", malformed_descriptors)
write_index.call("mismatched-reference-index.json", mismatched_reference_descriptors)
write_index.call("missing-reference-index.json", missing_reference_descriptors)
File.write(File.join(root, "oci-layout"), JSON.generate("imageLayoutVersion" => "1.0.0"))
RUBY

(cd "$test_root" && tar -cf "$test_root/good.tar" index.json oci-layout blobs)
for variant in bad missing-sbom missing-provenance empty-provenance bad-image-media-type malformed-image missing-image corrupt-image malformed-v02 mismatched-reference missing-reference; do
    mkdir "$test_root/$variant"
    index_variant="$variant"
    if [ "$variant" = missing-image ] || [ "$variant" = corrupt-image ]; then
        cp "$test_root/index.json" "$test_root/$variant/index.json"
    else
        cp "$test_root/$index_variant-index.json" "$test_root/$variant/index.json"
    fi
    cp -R "$test_root/blobs" "$test_root/$variant/"
    cp "$test_root/oci-layout" "$test_root/$variant/"
    if [ "$variant" = missing-image ]; then
        rm "$test_root/$variant/blobs/sha256/$(cat "$test_root/amd64-image-digest")"
    elif [ "$variant" = corrupt-image ]; then
        printf '%s\n' 'not-json' >"$test_root/$variant/blobs/sha256/$(cat "$test_root/amd64-image-digest")"
    fi
    (cd "$test_root/$variant" && tar -cf "$test_root/$variant.tar" index.json oci-layout blobs)
done

before_digest="$(sha256sum "$test_root/good.tar" | awk '{print $1}')"
if ! ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/good.tar" >/dev/null; then
    ruby "$(dirname "$0")/normalize-oci-attestations.rb" "$test_root/good.tar" >/dev/null
fi
ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/good.tar" >/dev/null
after_digest="$(sha256sum "$test_root/good.tar" | awk '{print $1}')"
[ "$before_digest" = "$after_digest" ] || {
    echo "descriptor-linked archive was rewritten" >&2
    exit 1
}
for variant in bad missing-sbom missing-provenance empty-provenance bad-image-media-type malformed-image missing-image corrupt-image malformed-v02 mismatched-reference missing-reference; do
    if ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/$variant.tar" >/dev/null 2>&1; then
        echo "invalid $variant archive was accepted" >&2
        exit 1
    fi
done

for layout in missing-layout bad-layout; do
    mkdir "$test_root/$layout"
    cp "$test_root/index.json" "$test_root/$layout/index.json"
    cp -R "$test_root/blobs" "$test_root/$layout/"
    if [ "$layout" = bad-layout ]; then
        printf '%s\n' '{"imageLayoutVersion":"0.9.0"}' >"$test_root/$layout/oci-layout"
    fi
    if [ "$layout" = bad-layout ]; then
        (cd "$test_root/$layout" && tar -cf "$test_root/$layout.tar" index.json oci-layout blobs)
    else
        (cd "$test_root/$layout" && tar -cf "$test_root/$layout.tar" index.json blobs)
    fi
done
if ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/missing-layout.tar" >/dev/null 2>&1 ||
   ruby "$(dirname "$0")/verify-oci-attestations.rb" "$test_root/bad-layout.tar" >/dev/null 2>&1; then
    echo "invalid OCI layout was accepted" >&2
    exit 1
fi

echo "OCI attestation inspection behavior passed"
