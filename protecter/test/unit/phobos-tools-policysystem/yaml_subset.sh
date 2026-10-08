#!/usr/bin/env bash
# Which YAML a policy may be written in, and the flat records the reader makes of it. The reader
# accepts a strict subset and refuses everything else, so a construct two YAML readers could read
# differently is refused instead of read one way; this suite pins both directions.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../src"
# shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Writes its standard input to a fixture and prints the records the reader makes of it, or
# "<status>|<message>" when the reader refuses it.
records_of() {
  local fixture="${WORK}/policy.yaml"
  local out="${WORK}/records"
  local message
  cat > "$fixture"
  message="$( (read_yaml_subset "$fixture" "$out") 2>&1 > /dev/null)"
  local status=$?
  if (( status == 0 )); then cat "$out"; else printf '%s|%s' "$status" "$message"; fi
}

echo "== accepted =="
expected=$'1\t.\tmap\t\n1\t.a\tint\t1\n2\t.b\tstr\tx y\n3\t.c\tbool\ttrue\n4\t.d\tnull\t'
actual="$(printf 'a: 1\nb: "x y"\nc: true\nd:\n' | records_of)"
check "scalars of every type" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.l\tseq\t\n2\t.l[0]\tmap\t\n2\t.l[0].k\tstr\tv\n3\t.l[0].n\tint\t0\n4\t.e\tseq\t'
actual="$(printf 'l:\n  - k: v\n    n: 0\ne: [ ]\n' | records_of)"
check "a sequence of mappings and an empty flow sequence" "$expected" "$actual"

actual="$(printf 'l:\n- k: v\n  n: 0\ne: []\n' | records_of)"
check "a sequence at its key's own column reads the same" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.s\tstr\tit'"'"$'s\n2\t.t\tstr\ta\\b"c'
actual="$(printf "s: 'it''s'\nt: \"a\\\\\\\\b\\\\\"c\"\n" | records_of)"
check "both quote styles and their escapes" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.m\tmap\t\n2\t.n\tmap\t\n3\t.o\tnull\t\n4\t.p\tnull\t\n5\t.q\tstr\tnull'
actual="$(printf 'm: {}\nn: { }\no: ~\np: NULL\nq: "null"\n' | records_of)"
check "empty flow mappings, the spellings of null, and a quoted null that is text" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.a\tmap\t\n2\t.a.b\tseq\t\n3\t.a.b[0]\tstr\tx\n4\t.a.b[1]\tstr\t/srv/a b\n5\t.a.c\tseq\t\n6\t.d\tnull\t'
actual="$(printf 'a:\n  b:\n  - x\n  - "/srv/a b"\n  c: []\nd: # nothing here\n' | records_of)"
check "a nested mapping, a list at its key's column inside it, and a key with only a comment" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.l\tseq\t\n2\t.l[0]\tmap\t\n2\t.l[0].k\tnull\t\n3\t.l[1]\tmap\t\n3\t.l[1].k\tstr\tx#y\n4\t.l[1].v\tseq\t\n5\t.l[1].v[0]\tstr\tz'
actual="$(printf 'l:\n  - k:\n  - k: x#y   # a hash inside a plain value stays\n    v:\n      - z\n' | records_of)"
check "the same key in two items is no duplicate, and a key with nothing after it is null" "$expected" "$actual"

expected=$'1\t.\tseq\t\n1\t[0]\tstr\ta\n2\t[1]\tint\t7'
actual="$(printf -- '- a\n- 7\n' | records_of)"
check "a list as the document" "$expected" "$actual"

expected=$'2\t.\tmap\t\n2\t.a\tint\t1'
actual="$(printf -- '---\na: 1 # comment with \xc3\xa4\n# a full-line comment\n' | records_of)"
check "a leading document marker and comments, any valid UTF-8 in a comment" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.p\tstr\t/srv/\xc3\xbcbung'
actual="$(printf 'p: "/srv/\xc3\xbcbung"\n' | records_of)"
check "a value with a non-ASCII name in valid UTF-8" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.a\tint\t1'
actual="$(printf 'a: 1' | records_of)"
check "a last line without a newline" "$expected" "$actual"

echo "== refused =="
for case in \
  'a: &x 1|anchor' 'a: *x|alias' 'a: !!str 1|tag' 'a: |\n  x|block scalar' 'a: ["-l"]|flow' \
  'a: 1\na: 2|appears twice' 'a: yes|true or false' 'a: True|true or false' 'a: 010|ambiguous' \
  'a: 0x10|ambiguous' 'a: 1.5|ambiguous' 'a: 1_000|ambiguous' 'a: 1:20|ambiguous' 'a: "x\\n"|escape' \
  'a: 1\n---\nb: 2|one document' 'a: 1\n...|one document' 'a: x\n  y|continuation' 'l:\n  -\n|alone' \
  '"a": 1|key' 'a: 1\r|carriage return' 'a: >\n  x|block scalar' 'a: {b: 1}|flow' 'a: -l|indicator' \
  'a: ::1|indicator' 'a: "\xc3\x28"|UTF-8' 'a: "x\xc2\x85y"|control' 'a: "x\xe2\x80\xaey"|bidirectional' 'a: 8e1|ambiguous' 'a: +80|ambiguous' \
  'a: 0o120|ambiguous' 'a: 80.0|ambiguous' 'a: on|true or false' 'a: n|true or false' \
  'a: "\xed\xa0\x80"|UTF-8' 'a: "\xf4\x90\x80\x80"|UTF-8' 'a: "\xc0\xaf"|UTF-8' 'a: "x\x01y"|control' \
  'a: "x\xe2\x81\xa6y"|bidirectional' 'a: x\xc2\x9fy|control' 'a: "x|unterminated' "a: 'x|unterminated" \
  'a: "x"y|after the closing quote' 'a: b: c|quote the value' '%YAML 1.2\na: 1|directive' 'a:\n  x|continuation' \
  'a:\n  b: 1\n c: 2|indentation' 'a: 1\n- x|list item' 'l:\n- x\n  - y|continuation' 'a b: 1|key' \
  'a: @x|indicator' 'a: `x|indicator' 'a: .inf|ambiguous' 'a: ? x|indicator' '\n# only a comment\n|no YAML content' \
  'a:b|neither' '--- a: 1|own line' 'a: [1]|flow' 'a: .INF|ambiguous' 'a: YES|true or false' 'a: oFf|true or false' \
  'a: "x\xef\xbb\xbfy"|byte order mark' '# a comment \xef\xbb\xbf\na: 1|byte order mark'; do
  text="${case%|*}"
  needle="${case##*|}"
  result="$(printf '%b\n' "$text" | records_of)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${needle}"* && "${result#*|}" == *"line "* ]]; then
    ok "refused, saying '${needle}' and a line: ${text}"
  else
    bad "refused, saying '${needle}' and a line: ${text}" "status ${PHB_EPOLICY}" "${result}"
  fi
done
for bytes in 'a:\t1\n' '\xef\xbb\xbfa: 1\n' 'a: 1\x00\n' '# a comment\t\n'; do
  result="$(printf '%b' "$bytes" | records_of)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" ]]; then ok "refused: ${bytes}"; else bad "refused: ${bytes}" "status ${PHB_EPOLICY}" "${result}"; fi
done

echo "== the line a refusal names =="
for case in 'a: 1\nb: 2\na: 3|line 3|first on line 1' 'a: 1\n\nb: yes|line 3|' 'a: x\n  y|line 2|' \
  'a: 1\nb: "\xc3\x28"|line 2|' 'a: 1\nb: 2\r|line 2|' 'l:\n  - k: 1\n    k: 2|line 3|first on line 2'; do
  text="${case%%|*}"
  rest="${case#*|}"
  where="${rest%%|*}"
  also="${rest#*|}"
  result="$(printf '%b\n' "$text" | records_of)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${where}."* && "${result#*|}" == *"${also}"* ]]; then
    ok "refused at ${where}: ${text}"
  else
    bad "refused at ${where}: ${text}" "status ${PHB_EPOLICY}, '${where}', '${also}'" "${result}"
  fi
done

finish
