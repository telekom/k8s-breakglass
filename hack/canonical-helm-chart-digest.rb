#!/usr/bin/env ruby
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Hash the semantic contents of a Helm package while ignoring tar/gzip
# timestamps and ownership metadata. Reading entries directly avoids trusting
# archive paths by extracting them into the filesystem.

require "digest"
require "rubygems/package"
require "zlib"

archive = ARGV.fetch(0) { abort "usage: canonical-helm-chart-digest.rb ARCHIVE" }
entries = []
seen = {}

def safe_name(name)
  normalized = name.sub(%r{/\z}, "")
  parts = normalized.split("/")
  abort "unsafe archive path: #{name}" if normalized.empty? || normalized.start_with?("/") || parts.any? { |part| part.empty? || part == "." || part == ".." }
  normalized
end

def safe_link_target(target)
  abort "unsafe archive link target: #{target}" if target.start_with?("/") || target.split("/").any? { |part| part == ".." }
end

Zlib::GzipReader.open(archive) do |gzip|
  Gem::Package::TarReader.new(gzip) do |tar|
    tar.each do |entry|
      # GNU/BSD tar may emit PAX metadata records before the real entry.
      next if ["x", "g"].include?(entry.header.typeflag)

      name = safe_name(entry.full_name)
      abort "duplicate archive path: #{name}" if seen[name]

      kind = if entry.directory?
               "d"
             elsif entry.file?
               "f"
             elsif entry.header.typeflag == "2"
               safe_link_target(entry.header.linkname)
               "l#{entry.header.linkname}"
             elsif entry.header.typeflag == "1"
               safe_link_target(entry.header.linkname)
               "h#{entry.header.linkname}"
             else
               abort "unsupported archive entry type for #{name}"
             end

      content = entry.file? ? entry.read : ""
      entries << [name, entry.header.mode.to_i & 0o7777, kind, content]
      seen[name] = true
    end
  end
end

digest = Digest::SHA256.new
entries.sort_by { |name, _mode, kind, _content| [name, kind] }.each do |name, mode, kind, content|
  [kind, name, mode.to_s, content.bytesize.to_s].each do |field|
    bytes = field.to_s.b
    digest.update([bytes.bytesize].pack("N"))
    digest.update(bytes)
  end
  digest.update(content.b)
end
puts digest.hexdigest
