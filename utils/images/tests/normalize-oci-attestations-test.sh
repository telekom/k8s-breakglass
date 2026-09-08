#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(mktemp -d "${TMPDIR:-/tmp}/oci-normalize-test.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM

ruby - "$root" <<'RUBY'
require "digest"
require "fileutils"
require "json"

root = ARGV.fetch(0)
blobs = File.join(root, "blobs", "sha256")
FileUtils.mkdir_p(blobs)
write = lambda do |value|
  payload = JSON.generate(value)
  digest = Digest::SHA256.hexdigest(payload)
  File.binwrite(File.join(blobs, digest), payload)
  { "mediaType" => "application/vnd.oci.image.manifest.v1+json", "digest" => "sha256:#{digest}", "size" => payload.bytesize }
end
config_payload = "{}"
config_digest = Digest::SHA256.hexdigest(config_payload)
File.binwrite(File.join(blobs, config_digest), config_payload)
config = { "mediaType" => "application/vnd.oci.image.config.v1+json", "digest" => "sha256:#{config_digest}", "size" => config_payload.bytesize }
image = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "config" => config, "layers" => [] }
image_payload = JSON.generate(image)
image_digest = Digest::SHA256.hexdigest(image_payload)
File.binwrite(File.join(blobs, image_digest), image_payload)
image_descriptor = { "mediaType" => image["mediaType"], "digest" => "sha256:#{image_digest}", "size" => image_payload.bytesize, "platform" => { "os" => "linux", "architecture" => "amd64" } }
statement = { "_type" => "https://in-toto.io/Statement/v1", "subject" => [], "predicateType" => "https://slsa.dev/provenance/v1", "predicate" => { "buildDefinition" => { "buildType" => "https://example.invalid/build" }, "runDetails" => { "builder" => { "id" => "https://example.invalid/builder" } } } }
statement_payload = JSON.generate(statement)
statement_digest = Digest::SHA256.hexdigest(statement_payload)
File.binwrite(File.join(blobs, statement_digest), statement_payload)
layer = { "mediaType" => "application/vnd.in-toto+json", "digest" => "sha256:#{statement_digest}", "size" => statement_payload.bytesize }
attestation = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.manifest.v1+json", "subject" => { "mediaType" => image["mediaType"], "digest" => "sha256:#{image_digest}", "size" => image_payload.bytesize }, "layers" => [layer] }
attestation_payload = JSON.generate(attestation)
attestation_digest = Digest::SHA256.hexdigest(attestation_payload)
File.binwrite(File.join(blobs, attestation_digest), attestation_payload)
attestation_descriptor = { "mediaType" => attestation["mediaType"], "digest" => "sha256:#{attestation_digest}", "size" => attestation_payload.bytesize, "annotations" => { "vnd.docker.reference.type" => "attestation-manifest", "vnd.docker.reference.digest" => "sha256:#{image_digest}" } }
index = { "schemaVersion" => 2, "mediaType" => "application/vnd.oci.image.index.v1+json", "manifests" => [image_descriptor, attestation_descriptor] }
File.write(File.join(root, "index.json"), JSON.generate(index))
File.write(File.join(root, "oci-layout"), JSON.generate("imageLayoutVersion" => "1.0.0"))
{
  "missing-reference" => ->(annotations) { annotations.delete("vnd.docker.reference.digest") },
  "malformed-reference" => ->(annotations) { annotations["vnd.docker.reference.digest"] = "not-a-digest" },
  "mismatched-reference" => ->(annotations) { annotations["vnd.docker.reference.digest"] = "sha256:#{"0" * 64}" }
}.each do |name, mutate|
  variant = JSON.parse(JSON.generate(index))
  mutate.call(variant["manifests"][1]["annotations"])
  variant_root = File.join(root, name)
  FileUtils.mkdir_p(variant_root)
  FileUtils.cp_r(File.join(root, "blobs"), variant_root)
  File.write(File.join(variant_root, "index.json"), JSON.generate(variant))
  File.write(File.join(variant_root, "oci-layout"), JSON.generate("imageLayoutVersion" => "1.0.0"))
  system("tar", "-cf", File.join(root, "#{name}.tar"), "-C", variant_root, "index.json", "oci-layout", "blobs", exception: true)
end
RUBY

(cd "$root" && tar -cf "$root/archive.tar" index.json oci-layout blobs)
ruby "$(dirname "$0")/normalize-oci-attestations.rb" "$root/archive.tar" >/dev/null
tar -tf "$root/archive.tar" | grep -Fxq oci-layout
tar -xOf "$root/archive.tar" oci-layout | grep -Fq '"1.0.0"'
for variant in missing-reference malformed-reference mismatched-reference; do
  if ruby "$(dirname "$0")/normalize-oci-attestations.rb" "$root/$variant.tar" >/dev/null 2>&1; then
    echo "invalid $variant archive was accepted" >&2
    exit 1
  fi
done
echo "OCI attestation normalizer behavior passed"
