#!/usr/bin/env ruby
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Validate the chart's public output as Kubernetes objects. This deliberately
# parses Helm's output instead of grepping YAML text: whitespace, key order,
# and comments are not part of the chart contract.
require "yaml"

mode, path = ARGV
abort "usage: validate-rendered.rb MODE RENDERED_FILE" unless mode && path

def fail_validation(message)
  abort "rendered catalogue validation failed: #{message}"
end

def expect(condition, message)
  fail_validation(message) unless condition
end

def value_at(object, *keys)
  keys.reduce(object) do |value, key|
    expect(value.is_a?(Hash) && value.key?(key), "missing #{keys.join(".")}")
    value[key]
  end
end

def objects_of(documents, kind)
  documents.select { |document| document.is_a?(Hash) && document["kind"] == kind }
end

begin
  # Helm emits ordinary JSON-compatible Kubernetes objects. Use Psych's
  # restricted visitor for every stream document so a rendered value cannot
  # instantiate arbitrary Ruby classes while being validated.
  stream = Psych.parse_stream(File.read(path))
  class_loader = Psych::ClassLoader::Restricted.new([], [])
  scanner = Psych::ScalarScanner.new(class_loader)
  visitor = Psych::Visitors::NoAliasRuby.new(scanner, class_loader)
  documents = stream.children.map { |document| visitor.accept(document.root) }.compact
rescue StandardError => error
  fail_validation("Helm output is not valid YAML: #{error.message}")
end

expect(!documents.empty?, "Helm produced no Kubernetes objects")
documents.each_with_index do |document, index|
  expect(document.is_a?(Hash), "document #{index + 1} is not a Kubernetes object")
  expect(document["apiVersion"] == "breakglass.t-caas.telekom.com/v1alpha1", "document #{index + 1} has an unexpected apiVersion")
  expect(%w[DebugPodTemplate DebugSessionTemplate].include?(document["kind"]), "document #{index + 1} has an unexpected kind")
end

pods = objects_of(documents, "DebugPodTemplate")
sessions = objects_of(documents, "DebugSessionTemplate")
expect(pods.length == sessions.length, "pod/session template cardinality differs")
expect(pods.length.positive?, "no enabled profiles were rendered")

pod_by_profile = pods.to_h { |object| [value_at(object, "metadata", "labels", "breakglass.t-caas.telekom.com/catalogue-profile"), object] }
session_by_profile = sessions.to_h { |object| [value_at(object, "metadata", "labels", "breakglass.t-caas.telekom.com/catalogue-profile"), object] }
expect(pod_by_profile.length == pods.length, "pod profile labels are not unique")
expect(session_by_profile.length == sessions.length, "session profile labels are not unique")

pods.each do |pod|
  metadata = value_at(pod, "metadata")
  labels = value_at(metadata, "labels")
  profile = value_at(labels, "breakglass.t-caas.telekom.com/catalogue-profile")
  intent = value_at(labels, "breakglass.t-caas.telekom.com/catalogue-intent")
  elevated_label = value_at(labels, "breakglass.t-caas.telekom.com/elevated")
  expect(profile.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/), "#{profile.inspect} is not a DNS-safe profile label")
  expect(intent.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/), "#{profile} has an invalid intent label")
  expect(%w[true false].include?(elevated_label), "#{profile} has a non-boolean elevation label")
  display_name = value_at(pod, "spec", "displayName")
  description = value_at(pod, "spec", "description")
  expect(display_name.is_a?(String) && !display_name.empty?, "#{profile} has no display name")
  expect(description.is_a?(String) && !description.empty?, "#{profile} has no description")

  pod_spec = value_at(pod, "spec", "template", "spec")
  container_list = value_at(pod_spec, "containers")
  expect(container_list.length == 1, "#{profile} must render exactly one debug container")
  container = container_list.first
  expect(container["name"] == "debug", "#{profile} container has an unstable name")
  expect(container["image"].is_a?(String) && !container["image"].empty?, "#{profile} has no image")
  expect(container["command"].is_a?(Array) && !container["command"].empty?, "#{profile} has no command")
  expect(container["args"].is_a?(Array), "#{profile} args are not an array")
  expect(container["imagePullPolicy"].is_a?(String), "#{profile} has no image pull policy")
  expect(value_at(container, "securityContext", "capabilities", "drop") == ["ALL"], "#{profile} must drop all capabilities")
  expect(value_at(container, "securityContext", "allowPrivilegeEscalation").is_a?(FalseClass), "#{profile} must disable privilege escalation")
  expect(value_at(container, "securityContext", "privileged").is_a?(FalseClass), "#{profile} must not be privileged") unless elevated_label == "true"
  expect(value_at(pod_spec, "restartPolicy") == "Never", "#{profile} must be a one-shot pod")
  expect(value_at(pod_spec, "enableServiceLinks").is_a?(FalseClass), "#{profile} must disable service links")
  expect(value_at(pod_spec, "hostIPC").is_a?(FalseClass), "#{profile} must disable host IPC")
  expect(value_at(container, "resources", "requests", "cpu") == "10m", "#{profile} has an unexpected CPU request")
  expect(value_at(container, "resources", "limits", "memory") == "256Mi", "#{profile} has an unexpected memory limit")

  session = session_by_profile.fetch(profile) { fail_validation("#{profile} has no paired DebugSessionTemplate") }
  session_name = value_at(session, "metadata", "name")
  expect(value_at(session, "spec", "podTemplateRef", "name") == metadata["name"], "#{profile} session does not reference its pod template")
  expect(value_at(session, "spec", "mode") == "workload", "#{profile} must use workload mode")
  expect(value_at(session, "metadata", "labels", "breakglass.t-caas.telekom.com/catalogue-intent") == intent, "#{profile} intent differs between paired objects")
  expect(session_name == metadata["name"], "#{profile} paired objects must share a stable name")
  expect(value_at(session, "spec", "failMode") == "closed", "#{profile} must fail closed")
  expect(value_at(session, "spec", "audit", "enabled").is_a?(TrueClass), "#{profile} must enable audit")
  expect(value_at(session, "spec", "requestReason", "mandatory").is_a?(TrueClass), "#{profile} must require a reason")
end

case mode
when "default"
  expect(pods.length == 2 && sessions.length == 2, "default fixture must render two paired profiles")
  expect(pods.all? { |object| value_at(object, "metadata", "labels", "breakglass.t-caas.telekom.com/elevated") == "false" }, "default profiles must not be elevated")
  pods.each do |pod|
    profile = value_at(pod, "metadata", "labels", "breakglass.t-caas.telekom.com/catalogue-profile")
    pod_spec = value_at(pod, "spec", "template", "spec")
    expect(value_at(pod_spec, "securityContext", "runAsNonRoot").is_a?(TrueClass), "#{profile} must require a non-root pod")
    expect(value_at(pod_spec, "securityContext", "seccompProfile", "type") == "RuntimeDefault", "#{profile} must use RuntimeDefault seccomp")
    expect(value_at(pod_spec, "automountServiceAccountToken").is_a?(FalseClass), "#{profile} must not receive a service-account token")
    expect(value_at(pod_spec, "hostNetwork").is_a?(FalseClass), "#{profile} must not use host networking")
    expect(value_at(pod_spec, "hostPID").is_a?(FalseClass), "#{profile} must not use host PID")
    container = value_at(pod_spec, "containers").first
    expect(value_at(container, "securityContext", "readOnlyRootFilesystem").is_a?(TrueClass), "#{profile} must use a read-only root filesystem")
  end
when "custom"
  expect(pod_by_profile.keys.sort == %w[custom-readonly direct-image], "custom fixture profiles were not rendered")
  expect(value_at(pod_by_profile.fetch("custom-readonly"), "spec", "template", "spec", "containers").first["image"] == "busybox:1.36.1", "custom image was not rendered")
  expect(value_at(pod_by_profile.fetch("direct-image"), "spec", "template", "spec", "containers").first["image"] == "busybox:1.36.1", "direct image was not rendered")
when "all"
  expected = %w[workload-diagnostics network-diagnostics storage-diagnostics dump-access network-repair node-recovery cluster-validation]
  expect(session_by_profile.keys == expected, "all-enabled profiles must preserve the declared intent order")
  expected.each do |profile|
    pod_spec = value_at(pod_by_profile.fetch(profile), "spec", "template", "spec")
    session_spec = value_at(session_by_profile.fetch(profile), "spec")
    elevated = value_at(pod_by_profile.fetch(profile), "metadata", "labels", "breakglass.t-caas.telekom.com/elevated") == "true"
    expect(value_at(pod_spec, "securityContext", "seccompProfile", "type") == "RuntimeDefault", "#{profile} must use RuntimeDefault seccomp")
    expect(value_at(pod_spec, "hostIPC").is_a?(FalseClass), "#{profile} must disable host IPC")
    expect(value_at(session_spec, "allowed", "groups") == ["catalogue-requesters"], "#{profile} requester groups are not wired")
    expect(value_at(session_spec, "approvers", "groups") == ["catalogue-approvers"], "#{profile} approver groups are not wired")
    expect(value_at(session_spec, "failMode") == "closed", "#{profile} lifecycle is not fail closed")
    if %w[workload-diagnostics storage-diagnostics cluster-validation].include?(profile)
      expect(!elevated, "#{profile} must stay restricted")
      expect(value_at(pod_spec, "securityContext", "runAsNonRoot").is_a?(TrueClass), "#{profile} must be non-root")
      expect(value_at(pod_spec, "automountServiceAccountToken").is_a?(FalseClass), "#{profile} must not receive a token") unless profile == "cluster-validation"
      expect(value_at(pod_spec, "containers").first.dig("securityContext", "readOnlyRootFilesystem").is_a?(TrueClass), "#{profile} must be read-only")
    end
    if %w[network-diagnostics network-repair node-recovery].include?(profile)
      expect(elevated, "#{profile} must explicitly opt into elevation")
      expect(value_at(pod_spec, "securityContext", "runAsUser") == 0, "#{profile} must run as UID 0")
      expect(value_at(pod_spec, "hostNetwork").is_a?(TrueClass), "#{profile} must use the elevated node network")
    end
  end
  cluster = pod_by_profile.fetch("cluster-validation")
  cluster_spec = value_at(cluster, "spec", "template", "spec")
  expect(value_at(cluster_spec, "automountServiceAccountToken").is_a?(TrueClass), "cluster validation must opt into its API identity")
  expect(value_at(cluster_spec, "serviceAccountName") == "cluster-validator", "cluster validation must use its dedicated service account")
  storage_mounts = value_at(pod_by_profile.fetch("storage-diagnostics"), "spec", "template", "spec", "containers").first.fetch("volumeMounts")
  expect(storage_mounts.map { |mount| mount["mountPath"] }.sort == %w[/reports /scratch /tmp], "storage diagnostics mounts are incomplete")
  dump_mounts = value_at(pod_by_profile.fetch("dump-access"), "spec", "template", "spec", "containers").first.fetch("volumeMounts")
  dump_input = dump_mounts.find { |mount| mount["mountPath"] == "/input" }
  expect(dump_input && dump_input["readOnly"].is_a?(TrueClass), "dump input must be read-only")
  %w[network-repair node-recovery].each do |node_profile|
    node_pod = value_at(pod_by_profile.fetch(node_profile), "spec", "template", "spec")
    node_container = value_at(node_pod, "containers").first
    node_env = value_at(node_container, "env")
    node_name = node_env.find { |entry| entry["name"] == "NODE_NAME" }
    expect(node_name == {"name" => "NODE_NAME", "valueFrom" => {"fieldRef" => {"fieldPath" => "spec.nodeName"}}}, "#{node_profile} must receive the Downward API node name")
  end
when "digest"
  expect(pods.length == 1 && sessions.length == 1, "digest fixture must render one paired profile")
  image = value_at(pods.first, "spec", "template", "spec", "containers").first["image"]
  expect(image == "example.invalid/workload-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "digest must be the immutable image reference")
when "elevated"
  expect(pods.length == 1 && sessions.length == 1, "elevated fixture must render one paired profile")
  pod_spec = value_at(pods.first, "spec", "template", "spec")
  expect(value_at(pod_spec, "securityContext", "runAsNonRoot").is_a?(FalseClass), "elevated profile must opt out of non-root")
  expect(value_at(pod_spec, "securityContext", "runAsUser") == 0, "elevated profile must run as UID 0")
  expect(value_at(pod_spec, "hostNetwork").is_a?(TrueClass), "elevated node profile must use host networking")
  volumes = value_at(pod_spec, "volumes")
  expect(volumes.any? { |volume| volume.key?("hostPath") && value_at(volume, "hostPath", "path") == "/var/lib/example" }, "elevated profile must render its requested host path")
else
  fail_validation("unknown validation mode #{mode.inspect}")
end

puts "rendered #{mode} catalogue validated: #{pods.length} paired profile(s)"
