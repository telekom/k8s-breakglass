#!/usr/bin/env ruby
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

require "digest"
require "fileutils"
require "json"
require "tmpdir"

archive = ARGV.fetch(0) { abort "OCI attestation normalization: archive path is required" }
abort "OCI attestation normalization: archive does not exist: #{archive}" unless File.file?(archive)

Dir.mktmpdir("oci-attestation-normalize") do |root|
  system("tar", "-xf", archive, "-C", root, exception: true)
  blob_path = lambda do |digest|
    abort "OCI attestation normalization: invalid digest #{digest}" unless digest.match?(/\Asha256:[0-9a-f]{64}\z/)

    File.join(root, "blobs", "sha256", digest.delete_prefix("sha256:"))
  end
  read_json = lambda do |digest|
    path = blob_path.call(digest)
    payload = File.binread(path)
    abort "OCI attestation normalization: digest mismatch for #{digest}" unless Digest::SHA256.hexdigest(payload) == digest.delete_prefix("sha256:")

    [path, JSON.parse(payload)]
  end
  write_json = lambda do |value|
    payload = JSON.generate(value)
    digest = "sha256:#{Digest::SHA256.hexdigest(payload)}"
    path = blob_path.call(digest)
    File.binwrite(path, payload)
    [digest, payload.bytesize]
  end

  rewrite_descriptor = lambda do |descriptor|
    media_type = descriptor["mediaType"].to_s
    return descriptor unless media_type == "application/vnd.oci.image.index.v1+json" ||
      media_type == "application/vnd.oci.image.manifest.v1+json"

    path, document = read_json.call(descriptor.fetch("digest"))
    changed = false
    if media_type == "application/vnd.oci.image.index.v1+json"
      document.fetch("manifests").each do |child|
        original_digest = child.fetch("digest")
        rewritten = rewrite_descriptor.call(child)
        changed ||= rewritten["digest"] != original_digest
        child.replace(rewritten)
      end
    elsif descriptor.dig("annotations", "vnd.docker.reference.type") == "attestation-manifest"
      reference = document.dig("subject", "digest").to_s
      annotation_reference = descriptor.dig("annotations", "vnd.docker.reference.digest").to_s
      abort "OCI attestation normalization: attestation subject is missing" unless reference.match?(/\Asha256:[0-9a-f]{64}\z/)
      abort "OCI attestation normalization: attestation reference mismatch" unless reference == annotation_reference

      document.fetch("layers").each do |layer|
        next unless layer["mediaType"] == "application/vnd.in-toto+json"

        layer_path, statement = read_json.call(layer.fetch("digest"))
        subject = statement["subject"]
        layer_changed = false
        if subject.nil? || !subject.is_a?(Array)
          abort "OCI attestation normalization: in-toto subject is malformed"
        elsif subject.empty?
          statement["subject"] = [{ "name" => "_", "digest" => { "sha256" => reference.delete_prefix("sha256:") } }]
          digest, size = write_json.call(statement)
          layer["digest"] = digest
          layer["size"] = size
          changed = true
          layer_changed = true
        else
          matches = subject.any? do |entry|
            entry.is_a?(Hash) &&
              entry.dig("digest", "sha256") == reference.delete_prefix("sha256:")
          end
          abort "OCI attestation normalization: in-toto subject does not match its image" unless matches
        end
        FileUtils.rm_f(layer_path) if layer_changed
      end
    end

    return descriptor unless changed

    digest, size = write_json.call(document)
    descriptor.merge("digest" => digest, "size" => size)
  end

  index_path = File.join(root, "index.json")
  index = JSON.parse(File.binread(index_path))
  index.fetch("manifests").map! { |descriptor| rewrite_descriptor.call(descriptor) }
  File.binwrite(index_path, JSON.generate(index))

  normalized = "#{archive}.normalized"
  system("tar", "-cf", normalized, "-C", root, "index.json", "blobs", exception: true)
  File.rename(normalized, archive)
end

puts "normalized OCI attestation subjects in #{archive}"
