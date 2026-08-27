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
attestations = descriptors.select do |descriptor|
  descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest"
end
fail_archive("BuildKit emitted no attestation manifests") if attestations.empty?

found_sbom = false
found_provenance = false
attestations.each do |descriptor|
  reference_digest = descriptor.dig("annotations", "vnd.docker.reference.digest").to_s
  fail_archive("attestation has no image subject reference") unless image_digests.include?(reference_digest)
  manifest = JSON.parse(read_blob(archive, descriptor, "attestation manifest"))
  subject_digest = manifest.dig("subject", "digest")
  fail_archive("attestation subject does not match its reference") if subject_digest && subject_digest != reference_digest
  layers = manifest["layers"]
  fail_archive("attestation manifest has no layers") unless layers.is_a?(Array) && !layers.empty?

  layers.each do |layer|
    media_type = layer["mediaType"].to_s
    next unless media_type == "application/vnd.in-toto+json"

    statement = JSON.parse(read_blob(archive, layer, "in-toto attestation"))
    predicate_type = statement["predicateType"].to_s
    predicate = statement["predicate"]
    if predicate_type.include?("spdx") || (predicate.is_a?(Hash) && predicate["spdxVersion"])
      found_sbom = true
    elsif predicate_type.include?("slsa")
      found_provenance = true
    end
  end
end

fail_archive("SPDX SBOM attestation is missing") unless found_sbom
fail_archive("SLSA provenance attestation is missing") unless found_provenance
puts "validated OCI archive #{archive} (#{platforms.sort.join(', ')}, SBOM, provenance)"
