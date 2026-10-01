#!/usr/bin/env bash
#
# verify-guard-mutations.sh: re-run the mutations that prove two guard tests
# still catch the defect they were written for.
#
# A guard test is only worth having if it FAILS when the thing it guards
# breaks. Each guard below was mutation-verified once, by hand, when it was
# written. This script repeats that: it applies the mutation to the tracked
# source, runs only that guard's test, checks that the test fails, and puts the
# source back.
#
#   1. internal/embeddings TestBindingAPIMatchesDownloadedRuntime
#      Mutation: `go get github.com/yalue/onnxruntime_go@v1.36.0`. That
#      binding's header declares ORT_API_VERSION 29, but onnxVersion still
#      downloads ONNX Runtime 1.23.2 (API 23). go.mod and go.sum are restored.
#   2. internal/writeperm TestExplainOwnReadOnlyFileIsNotForeign
#      Mutation: delete the `if owner == proc { return err }` early return in
#      Explain, so a 0400 file this user owns is reported as foreign-owned.
#
# Usage: scripts/verify-guard-mutations.sh   (from anywhere in the repo)
#
# A HEALTHY RUN looks like this. Each guard passes on the unmodified tree,
# then fails under its mutation and is reported "CAUGHT". The source is
# restored after each guard. The last lines say the restored files match HEAD
# byte for byte and `git status --porcelain` is empty. Exit status 0.
#
# FAILURE MODES, by exit status:
#
#   1  A guard did not do its job. The main case is UNEXPECTED PASS: the test
#      passed with the mutation applied, so the guard no longer catches the
#      defect. Such a result is printed in a banner. Also exit 1:
#        - BASELINE FAILED: the guard fails on the unmodified tree, so a
#          failure under mutation proves nothing.
#        - NOT RUN: the test skipped, or the package did not build, so there
#          is no test result for the mutation.
#      The other guard still runs, and every result is in the summary.
#   2  The driver could not do its job, and no guard was judged. Causes: the
#      working tree was dirty (it refuses rather than guess what to restore),
#      a required tool is missing, or a MUTATION DID NOT APPLY. In the last
#      case the source no longer matches the edit, or the edit changed
#      nothing. That is a hard error, never a pass: a mutation that applies
#      nothing makes every guard look healthy. Update the mutation to match
#      the current source.
#   3  RESTORE FAILED. The tracked files could not be put back to match HEAD,
#      or the tree is not clean afterwards. This outranks every other result.
#      Inspect `git status` and `git diff` yourself. The pre-mutation copies
#      are kept in the directory the script names.
#
# Restoring happens in an EXIT trap, so it also runs after an error, Ctrl-C,
# SIGTERM or SIGHUP. The script does not trust the restore: it compares each
# file with its snapshot and with HEAD, then requires a clean tree.
#
# This script is not wired into CI. It needs the onnxruntime_go v1.36.0 module,
# either in the module cache or from the network.

set -uo pipefail

ONNX_MODULE=github.com/yalue/onnxruntime_go
ONNX_MUTANT_VERSION=v1.36.0
WRITEPERM_FILE=internal/writeperm/writeperm.go
# The exact block the writeperm mutation removes, tabs included.
WRITEPERM_BLOCK=$'\tif owner == proc {\n\t\treturn err\n\t}\n'
# Every tracked file a mutation may touch. All are snapshotted before any edit.
TOUCHED_FILES=(go.mod go.sum "$WRITEPERM_FILE")

if [ -t 1 ]; then
	RED=$'\033[1;31m' GREEN=$'\033[1;32m' YELLOW=$'\033[1;33m' BOLD=$'\033[1m' RESET=$'\033[0m'
else
	RED='' GREEN='' YELLOW='' BOLD='' RESET=''
fi

say() { printf '%s\n' "$*"; }
die() { # die <status> <message...>
	local status=$1
	shift
	printf '%sERROR:%s %s\n' "$RED" "$RESET" "$*" >&2
	exit "$status"
}

for tool in git go perl cmp; do
	command -v "$tool" >/dev/null 2>&1 || die 2 "required tool '$tool' is not on PATH"
done

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || die 2 "not inside a git working tree"
cd "$ROOT" || die 2 "cannot cd to $ROOT"

# --- refuse a dirty tree -----------------------------------------------------

DIRTY=$(git status --porcelain --untracked-files=all)
if [ -n "$DIRTY" ]; then
	say "$DIRTY" >&2
	die 2 "the working tree is not clean (above). This script edits tracked source and restores it afterwards. On a dirty tree, 'restored' would be ambiguous: it could not tell your changes from its own. Commit or stash, then rerun."
fi

for f in "${TOUCHED_FILES[@]}"; do
	git ls-files --error-unmatch -- "$f" >/dev/null 2>&1 || die 2 "$f is not tracked; the mutations below no longer match this repository"
done

# --- snapshot, and restore on every exit path --------------------------------

WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-guard-mutations.XXXXXX") || die 2 "mktemp failed"
mkdir -p "$WORK/snapshot" "$WORK/logs"
for f in "${TOUCHED_FILES[@]}"; do
	mkdir -p "$WORK/snapshot/$(dirname "$f")"
	cp -p "$f" "$WORK/snapshot/$f" || die 2 "could not snapshot $f"
done

# restore_files copies every snapshot back and checks the result byte for byte
# against both the snapshot and HEAD. Running it twice is safe.
restore_files() {
	local f ok=0
	for f in "${TOUCHED_FILES[@]}"; do
		if ! cmp -s "$WORK/snapshot/$f" "$f"; then
			cp -p "$WORK/snapshot/$f" "$f" || { say "${RED}restore:${RESET} could not copy $f back" >&2; ok=1; continue; }
		fi
		if ! cmp -s "$WORK/snapshot/$f" "$f"; then
			say "${RED}restore:${RESET} $f still differs from its snapshot" >&2
			ok=1
		elif ! git show "HEAD:$f" | cmp -s - "$f"; then
			say "${RED}restore:${RESET} $f differs from HEAD" >&2
			ok=1
		fi
	done
	return $ok
}

on_exit() {
	local status=$?
	trap - EXIT INT TERM HUP
	say ""
	say "${BOLD}== restoring tracked files ==${RESET}"
	local restore_ok=0
	restore_files || restore_ok=1
	local porcelain
	porcelain=$(git status --porcelain --untracked-files=all)
	if [ -n "$porcelain" ]; then
		say "$porcelain" >&2
		restore_ok=1
	fi
	if [ $restore_ok -ne 0 ]; then
		say "${RED}RESTORE FAILED:${RESET} the tree is not back to HEAD (see above). Pre-mutation copies are in $WORK/snapshot." >&2
		exit 3
	fi
	say "${GREEN}restored:${RESET} ${TOUCHED_FILES[*]} match HEAD byte for byte; git status --porcelain is empty"
	rm -rf "$WORK"
	exit "$status"
}
trap on_exit EXIT
trap 'say "interrupted (SIGINT)" >&2; exit 130' INT
trap 'say "terminated (SIGTERM)" >&2; exit 143' TERM
trap 'say "hung up (SIGHUP)" >&2; exit 129' HUP

# --- running one guard -------------------------------------------------------

# run_guard <pkg> <test> <log>: runs only that test, and prints PASS, FAIL,
# SKIP or NORUN based on the test's own result line, not just go's exit status.
# Without that check, a compile error would count as a failure.
run_guard() {
	local pkg=$1 test=$2 log=$3
	go test -count=1 -v -run "^${test}\$" "./$pkg" >"$log" 2>&1
	if grep -q -- "^--- FAIL: ${test} " "$log"; then
		echo FAIL
	elif grep -q -- "^--- PASS: ${test} " "$log"; then
		echo PASS
	elif grep -q -- "^--- SKIP: ${test} " "$log"; then
		echo SKIP
	else
		echo NORUN
	fi
}

# The lines a test reported, e.g. the t.Errorf messages, indented for display.
show_test_output() {
	grep -E -- '_test\.go:[0-9]+:|^[[:space:]]{4,}' "$1" | head -n 12 | sed 's/^/      /'
}
show_log_tail() { tail -n 15 "$1" | sed 's/^/      /'; }

mutation_not_applied() { # hard error: never fall through to running the test
	say "${RED}MUTATION DID NOT APPLY:${RESET} $*" >&2
	die 2 "a mutation that does not apply would make the guard look healthy without testing it. Update the mutation in $0 to match the current source."
}

# --- the mutations -----------------------------------------------------------

mutate_onnx() {
	local before after count
	before=$(go list -m -f '{{.Version}}' "$ONNX_MODULE" 2>&1) || mutation_not_applied "go list -m $ONNX_MODULE failed: $before"
	[ "$before" != "$ONNX_MUTANT_VERSION" ] || mutation_not_applied "go.mod already requires $ONNX_MODULE $ONNX_MUTANT_VERSION, so moving to it changes nothing"
	say "  mutation: go get $ONNX_MODULE@$ONNX_MUTANT_VERSION (currently $before)"
	if ! go get "$ONNX_MODULE@$ONNX_MUTANT_VERSION" >"$WORK/logs/onnx-go-get.log" 2>&1; then
		show_log_tail "$WORK/logs/onnx-go-get.log" >&2
		mutation_not_applied "go get $ONNX_MODULE@$ONNX_MUTANT_VERSION failed"
	fi
	after=$(go list -m -f '{{.Version}}' "$ONNX_MODULE" 2>&1)
	[ "$after" = "$ONNX_MUTANT_VERSION" ] || mutation_not_applied "after go get, $ONNX_MODULE resolves to '$after', not $ONNX_MUTANT_VERSION"
	count=$(grep -c -F "$ONNX_MODULE $ONNX_MUTANT_VERSION" go.mod)
	[ "$count" = 1 ] || mutation_not_applied "go.mod names $ONNX_MODULE $ONNX_MUTANT_VERSION $count times, expected exactly 1"
	cmp -s go.mod "$WORK/snapshot/go.mod" && mutation_not_applied "go.mod is byte-identical to the original after go get"
	say "  applied:  go.mod now requires $ONNX_MODULE $after; changed:"
	git diff --stat -- go.mod go.sum | sed 's/^/    /'
}

# count_block <file>: the number of non-overlapping literal occurrences of
# WRITEPERM_BLOCK. remove_block deletes the one occurrence.
count_block() {
	BLOCK=$WRITEPERM_BLOCK perl -0777 -ne '
		my ($n, $p, $b) = (0, 0, $ENV{BLOCK});
		while (($p = index($_, $b, $p)) >= 0) { $n++; $p += length $b }
		print $n' "$1"
}
remove_block() {
	BLOCK=$WRITEPERM_BLOCK perl -0777 -i -pe '
		my $b = $ENV{BLOCK}; my $p = index($_, $b);
		substr($_, $p, length $b) = "" if $p >= 0' "$1"
}

mutate_writeperm() {
	local count
	say "  mutation: remove the 'if owner == proc { return err }' early return from Explain in $WRITEPERM_FILE"
	count=$(count_block "$WRITEPERM_FILE") || mutation_not_applied "could not read $WRITEPERM_FILE"
	[ "$count" = 1 ] || mutation_not_applied "the block occurs $count times in $WRITEPERM_FILE, expected exactly 1"
	remove_block "$WRITEPERM_FILE" || mutation_not_applied "perl could not edit $WRITEPERM_FILE"
	count=$(count_block "$WRITEPERM_FILE")
	[ "$count" = 0 ] || mutation_not_applied "the block is still present after the edit ($count occurrences)"
	cmp -s "$WRITEPERM_FILE" "$WORK/snapshot/$WRITEPERM_FILE" && mutation_not_applied "$WRITEPERM_FILE is byte-identical to the original after the edit"
	grep -q -F 'owner == proc' "$WRITEPERM_FILE" && mutation_not_applied "'owner == proc' still appears in $WRITEPERM_FILE"
	say "  applied:  $WRITEPERM_FILE changed:"
	git diff --stat -- "$WRITEPERM_FILE" | sed 's/^/    /'
}

# --- driving each guard ------------------------------------------------------

SUMMARY=()
WORST=0
note() { # note <status> <summary line>
	[ "$1" -gt "$WORST" ] && WORST=$1
	SUMMARY+=("$2")
}

# verify <name> <pkg> <test> <mutate-fn> <what>
verify() {
	local name=$1 pkg=$2 test=$3 mutate=$4 what=$5 base result
	say ""
	say "${BOLD}== guard: $pkg $test ==${RESET}"

	base=$(run_guard "$pkg" "$test" "$WORK/logs/$name-baseline.log")
	say "  baseline (unmodified tree): $base"
	if [ "$base" != PASS ]; then
		show_log_tail "$WORK/logs/$name-baseline.log"
	fi

	"$mutate"

	result=$(run_guard "$pkg" "$test" "$WORK/logs/$name-mutant.log")
	say "  expected under mutation: FAIL    got: $result"

	case "$result" in
	FAIL)
		show_test_output "$WORK/logs/$name-mutant.log"
		if [ "$base" = PASS ]; then
			say "  ${GREEN}CAUGHT${RESET}"
			note 0 "CAUGHT          $test  ($what)"
		else
			say "  ${YELLOW}BASELINE FAILED:${RESET} the test fails without the mutation too, so this failure proves nothing"
			note 1 "BASELINE FAILED $test  (baseline $base; fails with and without $what)"
		fi
		;;
	PASS)
		say "${RED}"
		say "  ################################################################"
		say "  ##  UNEXPECTED PASS: $test"
		say "  ##  passed with the mutation applied. This guard does NOT catch:"
		say "  ##    $what"
		say "  ################################################################${RESET}"
		show_test_output "$WORK/logs/$name-mutant.log"
		note 1 "UNEXPECTED PASS $test  (did not catch: $what)"
		;;
	SKIP)
		show_log_tail "$WORK/logs/$name-mutant.log"
		say "  ${YELLOW}NOT RUN:${RESET} the test skipped under mutation, so it verified nothing"
		note 1 "NOT RUN (SKIP)  $test  ($what)"
		;;
	*)
		show_log_tail "$WORK/logs/$name-mutant.log"
		say "  ${YELLOW}NOT RUN:${RESET} no result line for $test (did the package fail to build?)"
		note 1 "NOT RUN (BUILD) $test  ($what)"
		;;
	esac

	restore_files || die 3 "could not restore after mutating for $test"
	say "  restored ${TOUCHED_FILES[*]}"
}

verify onnx internal/embeddings TestBindingAPIMatchesDownloadedRuntime mutate_onnx \
	"$ONNX_MODULE moved to $ONNX_MUTANT_VERSION (API 29) against ONNX Runtime 1.23.2 (API 23)"
verify writeperm internal/writeperm TestExplainOwnReadOnlyFileIsNotForeign mutate_writeperm \
	"the 'owner == proc' early return removed from Explain"

say ""
say "${BOLD}== summary ==${RESET}"
for line in "${SUMMARY[@]}"; do
	say "  $line"
done
if [ "$WORST" -eq 0 ]; then
	say "${GREEN}all guards caught their mutations${RESET}"
else
	say "${RED}NOT HEALTHY: at least one guard did not catch its mutation (above)${RESET}"
fi
exit "$WORST"
