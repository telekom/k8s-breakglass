#!/usr/bin/env ruby
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Inspect a local OCI archive produced by BuildKit.  An archive can be
# structurally valid while silently omitting attestations, so this follows the
# descriptors into their blobs and validates the in-toto predicates as well.

require "digest"
require "json"
require "open3"

def fail_archive(message)
  warn "OCI attestation inspection: #{message}"
  exit 1
end

archive = ARGV.fetch(0) { fail_archive("archive path is required") }
fail_archive("archive does not exist: #{archive}") unless File.file?(archive)

def read_entry(archive, entry)
  output, error, status = Open3.capture3("tar", "-xOf", archive, entry)
  fail_archive("cannot read #{entry}: #{error.strip}") unless status.success?
  output
end

def descriptor_digest(descriptor, label)
  digest = descriptor["digest"].to_s
  fail_archive("#{label} has no sha256 digest") unless digest.match?(/\Asha256:[0-9a-f]{64}\z/)
  digest
end

def read_blob(archive, descriptor, label)
  digest = descriptor_digest(descriptor, label)
  payload = read_entry(archive, "blobs/sha256/#{digest.delete_prefix('sha256:')}")
  fail_archive("#{label} digest does not match its blob") unless Digest::SHA256.hexdigest(payload) == digest.delete_prefix("sha256:")
  payload
end

index = JSON.parse(read_entry(archive, "index.json"))
fail_archive("index is not an OCI image index") unless index["schemaVersion"] == 2 && index["mediaType"] == "application/vnd.oci.image.index.v1+json"

def flatten_index(archive, descriptor, flattened, visited)
  media_type = descriptor["mediaType"].to_s
  unless media_type == "application/vnd.oci.image.index.v1+json"
    flattened << descriptor
    return
  end

  digest = descriptor_digest(descriptor, "nested image index")
  return if visited.include?(digest)
  visited << digest
  nested = JSON.parse(read_blob(archive, descriptor, "nested image index"))
  fail_archive("nested image index has no manifest descriptors") unless nested["manifests"].is_a?(Array) && !nested["manifests"].empty?
  nested["manifests"].each { |child| flatten_index(archive, child, flattened, visited) }
end

root_descriptors = index["manifests"]
fail_archive("index has no manifest descriptors") unless root_descriptors.is_a?(Array) && !root_descriptors.empty?
descriptors = []
visited_indexes = []
root_descriptors.each { |descriptor| flatten_index(archive, descriptor, descriptors, visited_indexes) }

images = descriptors.select do |descriptor|
  platform = descriptor["platform"] || {}
  annotation = descriptor.dig("annotations", "vnd.docker.reference.type")
  annotation != "attestation-manifest" && platform["os"] == "linux" && %w[amd64 arm64].include?(platform["architecture"])
end
platforms = images.map { |descriptor| "#{descriptor.dig('platform', 'os')}/#{descriptor.dig('platform', 'architecture')}" }.uniq
fail_archive("archive is missing linux/amd64 or linux/arm64 image manifests") unless platforms.sort == %w[linux/amd64 linux/arm64]

image_digests = images.map { |descriptor| descriptor_digest(descriptor, "image manifest") }
image_attestations = {}
images.each do |descriptor|
  fail_archive("image manifest descriptor has unexpected media type") unless descriptor["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
  manifest = JSON.parse(read_blob(archive, descriptor, "image manifest"))
  fail_archive("image manifest has an invalid schema version") unless manifest["schemaVersion"] == 2
  fail_archive("image manifest has an unexpected media type") unless manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
  config = manifest["config"]
  fail_archive("image manifest has no valid config descriptor") unless config.is_a?(Hash) && config["mediaType"] == "application/vnd.oci.image.config.v1+json"
  descriptor_digest(config, "image config")
  layers = manifest["layers"]
  fail_archive("image manifest has no valid layers list") unless layers.is_a?(Array)
  layers.each { |layer| descriptor_digest(layer, "image layer") }
  digest = descriptor_digest(descriptor, "image manifest")
  image_attestations[digest] = { "platform" => "#{descriptor.dig('platform', 'os')}/#{descriptor.dig('platform', 'architecture')}", "sbom" => false, "provenance" => false }
end
attestations = descriptors.select do |descriptor|
  descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest"
end
fail_archive("BuildKit emitted no attestation manifests") if attestations.empty?

attestations.each do |descriptor|
  reference_digest = descriptor.dig("annotations", "vnd.docker.reference.digest").to_s
  fail_archive("attestation has no image subject reference") unless image_digests.include?(reference_digest)
  manifest = JSON.parse(read_blob(archive, descriptor, "attestation manifest"))
  subject_digest = manifest.dig("subject", "digest")
  fail_archive("attestation subject is missing or does not match its reference") unless subject_digest == reference_digest
  layers = manifest["layers"]
  fail_archive("attestation manifest has no layers") unless layers.is_a?(Array) && !layers.empty?

  layers.each do |layer|
    media_type = layer["mediaType"].to_s
    next unless media_type == "application/vnd.in-toto+json"

    statement = JSON.parse(read_blob(archive, layer, "in-toto attestation"))
    fail_archive("in-toto statement type is missing or unsupported") unless statement["_type"] == "https://in-toto.io/Statement/v1"
    subjects = statement["subject"]
    fail_archive("in-toto statement has no subjects") unless subjects.is_a?(Array) && !subjects.empty?
    subject_matches = subjects.any? do |subject|
      digest = subject.is_a?(Hash) ? subject["digest"] : nil
      digest.is_a?(Hash) && digest["sha256"] == reference_digest.delete_prefix("sha256:")
    end
    fail_archive("in-toto statement subject does not match its image") unless subject_matches
    predicate_type = statement["predicateType"].to_s
    predicate = statement["predicate"]
    if predicate_type.include?("spdx")
      fail_archive("SPDX predicate is empty or malformed") unless predicate.is_a?(Hash) && predicate["spdxVersion"].to_s.match?(/\ASPDX-\S+/) && predicate["packages"].is_a?(Array) && !predicate["packages"].empty?
      image_attestations.fetch(reference_digest)["sbom"] = true
    elsif predicate_type.include?("slsa")
      build_definition = predicate.is_a?(Hash) ? predicate["buildDefinition"] : nil
      run_details = predicate.is_a?(Hash) ? predicate["runDetails"] : nil
      fail_archive("SLSA predicate is empty or malformed") unless build_definition.is_a?(Hash) && build_definition["buildType"].is_a?(String) && !build_definition["buildType"].empty? && run_details.is_a?(Hash) && run_details.dig("builder", "id").is_a?(String) && !run_details.dig("builder", "id").empty?
      image_attestations.fetch(reference_digest)["provenance"] = true
    end
  end
end

image_attestations.each_value do |attestation|
  fail_archive("SPDX SBOM attestation is missing for #{attestation['platform']}") unless attestation["sbom"]
  fail_archive("SLSA provenance attestation is missing for #{attestation['platform']}") unless attestation["provenance"]
end
puts "validated OCI archive #{archive} (#{platforms.sort.join(', ')}, SBOM, provenance)"
