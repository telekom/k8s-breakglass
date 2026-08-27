#!/usr/bin/env ruby
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Validate the machine-readable image release contract.  This intentionally
# checks relationships between fields; parsing YAML alone would allow a stale
# or disconnected contract to pass CI. Runtime claims are checked by the
# Docker-backed integration harness against the built image.

require "yaml"

def fail_contract(message)
  warn "image metadata: #{message}"
  exit 1
end

def require_value(value, message)
  fail_contract(message) if value.nil? || (value.respond_to?(:empty?) && value.empty?)
  value
end

def require_hash(value, message)
  fail_contract(message) unless value.is_a?(Hash)
  value
end

def require_array(value, message)
  fail_contract(message) unless value.is_a?(Array) && !value.empty?
  value
end

metadata_file = ARGV.fetch(0) { fail_contract("metadata path is required") }
repo_root = File.expand_path("..", __dir__)
metadata_path = File.expand_path(metadata_file, repo_root)
fail_contract("metadata file does not exist: #{metadata_file}") unless File.file?(metadata_path)

document = YAML.safe_load(File.read(metadata_path), aliases: false)
require_hash(document, "document must be a mapping")

modern = document["context"] && document["base"] && document["runtime"]
if modern
  image_name = require_value(document["image"], "image is required")
  context_name = require_value(document["context"], "context is required")
  base = require_hash(document["base"], "base must be a mapping")
  runtime = require_hash(document["runtime"], "runtime must be a mapping")
  contract = require_hash(document["contract"], "contract must be a mapping")
  attestations = require_hash(document["attestations"], "attestations must be a mapping")
  signing = require_hash(document["signing"], "signing must be a mapping")
  platforms = require_array(document["platforms"], "platforms must be a non-empty list")
  base_image = require_value(base["image"], "base.image is required")
  base_digest = require_value(base["digest"], "base.digest is required")
else
  schema = document["schemaVersion"]
  fail_contract("unsupported metadata schema") unless schema == 1
  image = require_hash(document["image"], "image must be a mapping")
  base = require_hash(image["base"], "image.base must be a mapping")
  provenance = require_hash(document["provenance"], "provenance must be a mapping")
  sbom = require_hash(provenance["sbom"], "provenance.sbom must be a mapping")
  signing = require_hash(provenance["signing"], "provenance.signing must be a mapping")
  image_name = require_value(image["name"], "image.name is required")
  context_name = File.dirname(metadata_file)
  platforms = require_array(image["platforms"], "image.platforms must be a non-empty list")
  base_image = require_value(base["name"], "image.base.name is required")
  base_digest = require_value(base["digest"], "image.base.digest is required")
  fail_contract("provenance.sbom.format must be spdx-json") unless sbom["format"] == "spdx-json"
  fail_contract("provenance.sbom.command must be executable") unless sbom["command"].to_s.include?("syft")
  fail_contract("provenance.signing.tool must be cosign") unless signing["tool"] == "cosign"
  fail_contract("provenance.signing.mode must be keyless") unless signing["mode"] == "keyless"
  require_array(signing["commands"], "provenance.signing.commands must be a non-empty list")
end

expected_platforms = ["linux/amd64", "linux/arm64"]
fail_contract("platform declarations must be exactly linux/amd64 and linux/arm64") unless platforms == expected_platforms
fail_contract("base digest is not an immutable sha256 digest") unless base_digest.match?(/\Asha256:[0-9a-f]{64}\z/)

context_components = context_name.split("/")
fail_contract("context must be a relative repository path") if context_name.start_with?("/") || context_name.empty? || context_components.include?("..") || context_components.include?("")
fail_contract("image name must match the context directory") if modern && image_name.to_s != File.basename(context_name)

if modern
  runtime_user = require_value(runtime["user"], "runtime.user is required")
  fail_contract("runtime.user must be numeric uid:gid") unless runtime_user.match?(/\A[0-9]+:[0-9]+\z/)
  fail_contract("runtime.user must not be root") if runtime_user.split(":", 2).first == "0"
  fail_contract("runtime.capabilities must be an empty list") unless runtime["capabilities"] == []
  fail_contract("runtime.privileged must be false") unless runtime["privileged"] == false
  fail_contract("runtime.network_required must be false") unless runtime["network_required"] == false

  executable = require_value(contract["executable"], "contract.executable is required")
  fail_contract("contract.executable must be absolute") unless executable.start_with?("/")
  executable_parts = executable.split("/")
  fail_contract("contract.executable must name a simple executable") unless File.basename(executable) == executable_parts.last && !File.basename(executable).empty? && !executable_parts.include?("..")
  dependencies = require_array(document["dependencies"], "dependencies must be a non-empty list")
  dependencies.each do |dependency|
    dependency = require_hash(dependency, "each dependency must be a mapping")
    require_value(dependency["name"], "dependency.name is required")
    require_value(dependency["version"], "dependency.version is required")
  end
  require_array(contract["intents"], "contract.intents must be a non-empty list")
  modes_or_commands = contract["modes"] || contract["commands"]
  require_array(modes_or_commands, "contract.modes or contract.commands must be a non-empty list")
  bounds = contract["bounds"]
  if bounds
    require_hash(bounds, "contract.bounds must be a mapping").each do |name, value|
      fail_contract("contract.bounds.#{name} must be a positive integer") unless value.is_a?(Integer) && value.positive?
    end
  end
  fail_contract("SBOM attestation is not required") unless attestations["sbom"] == "required"
  fail_contract("provenance attestation is not required") unless attestations["provenance"] == "required"
  fail_contract("signature must use keyless Cosign") unless attestations["signature"] == "cosign-keyless"
  fail_contract("signing tool must be Cosign") unless signing["tool"] == "cosign"
  fail_contract("signing identity must be keyless") unless signing["identity"] == "keyless"
  fail_contract("signing verification must target an immutable digest") unless signing["verify_command"].to_s.include?("@DIGEST")

end

puts "validated #{metadata_file} (#{image_name})"
