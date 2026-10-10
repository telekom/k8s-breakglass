#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ruby -rjson -ryaml - <<'RUBY'
chart = "charts/escalation-config"
[nil, {}, {"labels" => {"app.kubernetes.io/name" => "custom-config",
                  "breakglass.t-caas.telekom.com/debug-sessions-enabled" => "false",
                  "breakglass.t-caas.telekom.com/platform-diagnostics" => "true"},
      "annotations" => {"example.com/owner" => "platform"}}].each do |metadata|
  require "open3"
  output, error, status = Open3.capture3(
    "helm", "template", "metadata-proof", chart,
    "--values", "#{chart}/ci/test-values.yaml", "--values", "-",
    stdin_data: JSON.generate({"clusterConfig" => metadata}))
  abort error unless status.success?
  documents = YAML.load_stream(output).compact
  config = documents.find { |doc| doc["kind"] == "ClusterConfig" }
  abort "ClusterConfig missing" unless config
  labels = config.fetch("metadata").fetch("labels")
  abort "default chart label missing" unless labels.key?("helm.sh/chart")
  (metadata || {}).fetch("labels", {}).each do |key, value|
    abort "label #{key} missing or changed" unless labels[key] == value
  end
  if metadata && !metadata.empty?
    abort "annotations changed" unless config["metadata"]["annotations"] == metadata["annotations"]
    documents.reject { |doc| doc["kind"] == "ClusterConfig" }.each do |doc|
      abort "ClusterConfig label leaked to #{doc['kind']}" if doc.dig("metadata", "labels", "breakglass.t-caas.telekom.com/debug-sessions-enabled")
    end
  end
end
puts "Portable ClusterConfig metadata plain Helm render PASS"
RUBY
