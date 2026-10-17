#!/usr/bin/env bash
#
# check-action-pins.sh: fail when the same action is pinned to different refs
# in different places under .github/.
#
# Dependabot bumps each `uses:` line on its own, so one action can end up
# pinned to two digests: one in a workflow, one in a composite action. That
# has happened with msys2/setup-msys2. This script finds those cases.
#
# It parses every .yml and .yaml file under .github/, at any depth, as YAML
# (Ruby's standard-library Psych), so it finds a `uses` key in any mapping,
# block or flow (`- {uses: a/b@c}`), with any scalar style: plain, quoted,
# folded or literal. Text inside a scalar, such as a `run: |` script, is never
# a key, so it is never read as a use. An alias (`uses: *pin`) is resolved to
# its anchor's value.
#
# Each remote value of the form owner/repo[/subpath]@ref is grouped by
# owner/repo, so github/codeql-action/init and github/codeql-action/analyze
# are in the same group. Local uses (./ or ../) and docker:// uses are
# counted and skipped. Any group with two or more uses is compared, and every
# use in it is printed with its file, the line of its `uses` key, and its ref.
#
# A ref is a DIGEST if it is 40 or 64 hex characters, and a TAG otherwise.
# A group fails when:
#   DIVERGENT     its uses have more than one ref.
#   INCOMPARABLE  it mixes digests and tags. Offline, there is no way to tell
#                 whether a tag points at a given digest, so they are never
#                 treated as equal.
#
# Usage: scripts/check-action-pins.sh   (from anywhere in the repo)
#
# Exit status:
#   0  every group with two or more uses has the same ref. The output gives
#      the scan counts and lists each group compared, or says that no action
#      is pinned more than once.
#   1  at least one group is DIVERGENT or INCOMPARABLE. Every use involved is
#      printed.
#   2  the check could not run: not in a git tree, ruby missing, no YAML
#      files found, a file that is not valid YAML, or a `uses` value that is
#      not a string or cannot be parsed as owner/repo[/path]@ref.
#
# Limits: every `uses` key in every mapping counts, at any depth. A
# `with:` input that happens to be named `uses` would be read as an action.
# A step pulled in through a `<<:` merge key is counted once, where its
# anchor is defined.

set -uo pipefail

die() { # die <status> <message...>
	local status=$1
	shift
	printf 'ERROR: %s\n' "$*" >&2
	exit "$status"
}

command -v ruby >/dev/null 2>&1 || die 2 "ruby is required (it ships with Psych, the YAML parser used here)"
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || die 2 "not inside a git working tree"
cd "$ROOT" || die 2 "cannot cd to $ROOT"
[ -d .github ] || die 2 "no .github directory in $ROOT"

# Kept compatible with Ruby 2.6, the version macOS ships.
exec ruby -rpsych - <<'RUBY'
if $stdout.tty?
  RED, GREEN, BOLD, RESET = "\e[1;31m", "\e[1;32m", "\e[1m", "\e[0m"
else
  RED = GREEN = BOLD = RESET = ""
end

def die(msg)
  $stderr.puts "#{RED}ERROR:#{RESET} #{msg}"
  exit 2
end

files = Dir.glob(".github/**/*.{yml,yaml}", File::FNM_DOTMATCH)
           .select { |f| File.file?(f) && !File.symlink?(f) }
           .map { |f| f.sub(%r{\A\./}, "") }
           .uniq.sort
die "no .yml or .yaml files under .github" if files.empty?

def each_node(node, &blk)
  return if node.nil?
  yield node
  (node.children || []).each { |c| each_node(c, &blk) }
end

# Every `uses` key in a stream, as [line, value-or-nil, description].
def uses_in(stream)
  anchors = {}
  # An Alias node's `anchor` is the name it refers to, so skip aliases here.
  each_node(stream) do |n|
    next if n.is_a?(Psych::Nodes::Alias) || !n.respond_to?(:anchor) || n.anchor.nil?
    anchors[n.anchor] = n
  end
  found = []
  each_node(stream) do |n|
    next unless n.is_a?(Psych::Nodes::Mapping)
    n.children.each_slice(2) do |key, val|
      next unless key.is_a?(Psych::Nodes::Scalar) && key.value == "uses"
      val = anchors[val.anchor] if val.is_a?(Psych::Nodes::Alias)
      line = key.start_line + 1
      if val.is_a?(Psych::Nodes::Scalar)
        found << [line, val.value.strip, nil]
      else
        found << [line, nil, val.nil? ? "unresolved alias" : "a #{val.class.name.split('::').last.downcase}, not a string"]
      end
    end
  end
  found
end

REMOTE = %r{\A([^/@\s]+)/([^/@\s]+)(/[^@\s]+)?@([^@\s]+)\z}
records = []
bad = []
nlocal = ndocker = 0

files.each do |file|
  begin
    stream = Psych.parse_stream(File.read(file), filename: file)
  rescue Psych::SyntaxError => e
    die "#{file} is not valid YAML: #{e.message}"
  end
  uses_in(stream).each do |line, v, why|
    if v.nil?
      bad << "#{file}:#{line}: #{why}"
    elsif v.start_with?("./", "../")
      nlocal += 1
    elsif v.start_with?("docker://")
      ndocker += 1
    elsif (m = REMOTE.match(v))
      ref = m[4]
      digest = (ref.length == 40 || ref.length == 64) && ref =~ /\A\h+\z/
      ref = ref.downcase if digest
      records << { group: "#{m[1]}/#{m[2]}", file: file, line: line,
                   action: v[0, v.index("@")], ref: ref, kind: digest ? "digest" : "tag" }
    else
      bad << "#{file}:#{line}: #{v.empty? ? '(empty)' : v.inspect}"
    end
  end
end

groups = records.group_by { |r| r[:group] }
puts "#{BOLD}Scanned#{RESET} #{files.size} files: #{records.size} remote uses in #{groups.size} actions, " \
     "#{nlocal} local and #{ndocker} docker uses skipped."

unless bad.empty?
  puts "\n#{RED}UNPARSEABLE#{RESET}: #{bad.size} uses are not owner/repo[/path]@ref:"
  bad.each { |b| puts "  #{b}" }
  exit 2
end

compared = failed = 0
groups.keys.sort.each do |g|
  rs = groups[g].sort_by { |r| [r[:file], r[:line]] }
  next if rs.size < 2
  compared += 1
  refs = rs.map { |r| r[:ref] }.uniq
  if rs.map { |r| r[:kind] }.uniq.size > 1
    status = "#{RED}INCOMPARABLE#{RESET} (digest and tag refs mixed; offline equality cannot be established)"
    failed += 1
  elsif refs.size > 1
    status = "#{RED}DIVERGENT#{RESET} (#{refs.size} different refs)"
    failed += 1
  else
    status = "#{GREEN}OK#{RESET}"
  end
  puts "\n#{BOLD}#{g}#{RESET}: #{rs.size} uses, #{status}"
  rs.each { |r| puts "  #{r[:file]}:#{r[:line]}  #{r[:action]}@#{r[:ref]}  (#{r[:kind]})" }
end

puts
if compared.zero?
  puts "#{GREEN}OK#{RESET}: no action is pinned more than once, so there was nothing to compare."
elsif failed > 0
  puts "#{RED}FAIL#{RESET}: #{failed} of #{compared} actions used more than once have mismatched pins."
  exit 1
else
  puts "#{GREEN}OK#{RESET}: all #{compared} actions used more than once have the same pin everywhere."
end
exit 0
RUBY
