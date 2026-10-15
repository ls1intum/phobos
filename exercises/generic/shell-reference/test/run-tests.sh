#!/bin/bash
# The tester of the generic reference exercise. Each case uses one group of the shell tools the generic
# image ships and compares what it printed with the value it must print. A case runs in a subshell under
# set -euo pipefail, and each tool's output is taken in an assignment of its own before it is compared,
# so a tool that fails fails the case even when its output looked right. The JUnit report names every
# case, so that the layer pruner and the acceptance suite can tell a passing reference from one whose
# cases did not run.
set -u
SOLUTION="$(cd .. && pwd)/assignment/wordfreq.sh"
REPORT="$(cd .. && pwd)/test-reports/results.xml"
SCRATCH="$(mktemp -d)"
CASES=(bash solution sort_uniq_wc cut_tr_head_tail_cat mktemp find_xargs grep sed awk diff make words)

# bash itself: arithmetic and a here-string.
case_bash() {
  local output
  output="$(/bin/bash -c 'read -r x <<<"6"; echo $(( x * 7 ))')"
  [[ "${output}" == 42 ]]
}

# The solution on a small text.
case_solution() {
  local output
  printf 'b a B\nc a a\n' > "${SCRATCH}/text"
  output="$(/bin/bash "${SOLUTION}" "${SCRATCH}/text")"
  [[ "${output}" == $'a 3\nb 2\nc 1' ]]
}

# sort, uniq and wc.
case_sort_uniq_wc() {
  local output
  output="$(printf 'x\ny\nx\n' | sort | uniq | wc -l)"
  [[ "${output// /}" == 2 ]]
}

# cut, tr, head, tail and cat.
case_cut_tr_head_tail_cat() {
  local output
  output="$(printf 'a:b:c\nd:e:f\ng:h:i\n' | cat | head -n 2 | tail -n 1 | cut -d: -f2 | tr 'e' 'E')"
  [[ "${output}" == E ]]
}

# mktemp, in /tmp.
case_mktemp() {
  local file
  local content
  file="$(mktemp)"
  printf 'z' > "${file}"
  content="$(cat "${file}")"
  rm -f -- "${file}"
  [[ "${content}" == z ]]
}

# find and xargs.
case_find_xargs() {
  local output
  mkdir -p "${SCRATCH}/tree/sub"
  : > "${SCRATCH}/tree/sub/one.txt"
  : > "${SCRATCH}/tree/two.txt"
  output="$(find "${SCRATCH}/tree" -name '*.txt' -print0 | xargs -0 -n 1 basename | sort)"
  [[ "${output}" == $'one.txt\ntwo.txt' ]]
}

# grep.
case_grep() {
  local output
  output="$(printf 'alpha\nbeta\ngamma\ndelta x\n' | grep -c 'a$')"
  [[ "${output}" == 3 ]]
}

# sed.
case_sed() {
  local output
  output="$(printf 'hello world\n' | sed -E 's/(o)/0/g')"
  [[ "${output}" == "hell0 w0rld" ]]
}

# awk, which Debian provides as gawk.
case_awk() {
  local output
  output="$(printf '1 2\n3 4\n' | awk '{ s += $1 * $2 } END { print s }')"
  [[ "${output}" == 14 ]]
}

# diff: an equal pair ends with 0, an unequal pair with exactly 1 and the expected difference.
case_diff() {
  local status=0
  local output
  printf 'a\nb\n' > "${SCRATCH}/left"
  printf 'a\nc\n' > "${SCRATCH}/right"
  diff "${SCRATCH}/left" "${SCRATCH}/left"
  diff "${SCRATCH}/left" "${SCRATCH}/right" > "${SCRATCH}/diff.out" || status=$?
  [[ "${status}" == 1 ]]
  output="$(cat "${SCRATCH}/diff.out")"
  [[ "${output}" == $'2c2\n< b\n---\n> c' ]]
}

# make, on a makefile of its own.
case_make() {
  local output
  printf 'all:\n\t@echo built\n' > "${SCRATCH}/makefile"
  output="$(make -s -f "${SCRATCH}/makefile")"
  [[ "${output}" == built ]]
}

# The solution on a text with mixed case and punctuation.
case_words() {
  local output
  printf 'To be, or not to be.\n' > "${SCRATCH}/quote"
  output="$(/bin/bash "${SOLUTION}" "${SCRATCH}/quote" | head -n 2)"
  [[ "${output}" == $'be 2\nto 2' ]]
}

# Writes the JUnit report from the array RESULTS, one "name status" per case.
write_report() {
  local failures=0
  local entry
  local body=""
  for entry in "${RESULTS[@]}"; do
    if [[ "${entry#* }" == 0 ]]; then
      body+="    <testcase classname=\"generic\" name=\"${entry%% *}\"/>"$'\n'
    else
      failures=$((failures + 1))
      body+="    <testcase classname=\"generic\" name=\"${entry%% *}\"><failure message=\"status ${entry#* }\"/></testcase>"$'\n'
    fi
  done
  mkdir -p "$(dirname "${REPORT}")"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n  <testsuite name="generic" tests="%s" failures="%s" errors="0" skipped="0">\n%s  </testsuite>\n</testsuites>\n' \
    "${#RESULTS[@]}" "${failures}" "${body}" > "${REPORT}"
}

RESULTS=()
for name in "${CASES[@]}"; do
  ( set -euo pipefail; "case_${name}" ) > "${SCRATCH}/${name}.log" 2>&1
  status=$?
  RESULTS+=("${name} ${status}")
  if [[ "${status}" == 0 ]]; then
    printf '%s passed\n' "${name}"
  else
    printf '%s failed\n' "${name}"
  fi
done
write_report
rm -rf -- "${SCRATCH}"
