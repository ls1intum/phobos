#!/usr/bin/env bash
# phobos-policysystem.sh builds a run's specification from the base and exercise configuration. It
# is the one program that discovers the base policy, parses, merges and writes the spec files,
# and it is callable on its own, so a single layer can be run standalone over a directory it
# fills. No Landlock kernel is needed: this only checks the files it writes and that a layer
# can then be run over them with a pass-through stand-in for phobos-landlock-filesystem-and-networksystem.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../core"
# shellcheck source=../../core/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# A concrete writable directory for the test policies to grant, kept distinct from where the spec
# directories are made. phobos-policysystem.sh now refuses a specification that lies beneath a write
# path, exactly as a real run's /var/tmp spec parent lies outside the shipped policies' write
# paths, so a test that granted write to the spec's own parent would be refused for the right
# reason. fresh_spec makes specs directly under WORK, which this subdirectory is not an ancestor of.
WRITABLE="$WORK/writable"
mkdir -p "$WRITABLE"

CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n[execute]\n/usr\n[write]\n%s\n[create]\n%s\n[limits]\nmem_mb=64\n' \
  "$WRITABLE" "$WRITABLE" > "$CORE_X/BaseTest.cfg"

# Makes an empty, owned specification directory the way phobos.sh does, and prints its path.
fresh_spec() {
  local dir
  dir="$(mktemp -d "$WORK/spec.XXXXXX")"
  mkdir -p "$dir/scratch"
  printf '%s' "$dir"
}

echo "== phobos-policysystem.sh writes the specification files =="
SPEC="$(fresh_spec)"
# The policy is additive: an exercise config adds paths, rights and the larger limit on top
# of the base. Here it only raises a limit; the base paths are all carried through.
printf '[limits]\nmem_mb=128\n' > "$WORK/exercise.cfg"
bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$SPEC" --config "$WORK/exercise.cfg"
rc=$?
if [[ "$rc" -eq 0 ]]; then ok "a base and an exercise config build a specification"; else bad "a base and an exercise config build a specification" "exit 0" "exit $rc"; fi
check "the base read path is carried through"    "/usr" "$(cat "$SPEC/read.paths")"
check "the base execute path is carried through" "/usr" "$(cat "$SPEC/execute.paths")"
check "the base write path is carried through"   "$WRITABLE" "$(cat "$SPEC/write.paths")"
check "the base create path is carried through"  "$WRITABLE" "$(cat "$SPEC/create.paths")"
# limits.conf also carries the default for every key no cfg named, so this reads the one line
# the merge is about rather than the whole file.
check "the largest memory limit wins in the merge" "mem_mb=128" "$(grep '^mem_mb=' "$SPEC/limits.conf")"
check "a path no config named is absent from the spec" "" "$(grep -F /never/granted "$SPEC/read.paths")"

echo
echo "== an exercise adds to the base and cannot remove a base right =="
# Naming a base path in one section only adds; it does not strip the base's other rights on
# that path. Listing /usr in [read] leaves the base's execute right on /usr in place.
NSPEC="$(fresh_spec)"
printf '[read]\n/usr\n' > "$WORK/reaffirm.cfg"
bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$NSPEC" --config "$WORK/reaffirm.cfg" >/dev/null 2>&1
check "the base read right is kept"                 "/usr" "$(cat "$NSPEC/read.paths")"
check "the base execute right is not removed"       "/usr" "$(cat "$NSPEC/execute.paths")"
# An exercise may grant a right, and name a path, the base did not: the model is additive.
WSPEC="$(fresh_spec)"
printf '[write]\n/usr\n[read]\n/opt/extra\n' > "$WORK/widen.cfg"
out="$(bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$WSPEC" --config "$WORK/widen.cfg" 2>&1)"
rc=$?
if [[ "$rc" -eq 0 ]]; then ok "an exercise widening the sandbox is accepted (additive model)"; else bad "an exercise widening the sandbox is accepted (additive model)" "exit 0" "exit $rc: $out"; fi
check "the exercise adds write on a base path"      "/usr"       "$(grep -Fx /usr "$WSPEC/write.paths")"
check "the base write path is still present"         "$WRITABLE"  "$(grep -Fx "$WRITABLE" "$WSPEC/write.paths")"
check "the exercise adds a path the base did not"    "/opt/extra" "$(grep -Fx /opt/extra "$WSPEC/read.paths")"

echo
echo "== phobos-policysystem.sh refuses when there is no base policy =="
NOBASE="$WORK/nobase"
cp -R "$CORE" "$NOBASE"
chmod +x "$NOBASE"/*.sh
SPEC2="$(fresh_spec)"
out="$(bash "$NOBASE/phobos-policysystem.sh" --spec-dir "$SPEC2" 2>&1)"
rc=$?
if [[ "$rc" -eq "$PHB_EPOLICY" && "$out" == *"PHB-EPOLICY"* ]]; then
  ok "no Base*.cfg beside the policy program is refused (PHB-EPOLICY)"
else
  bad "no Base*.cfg beside the policy program is refused (PHB-EPOLICY)" "exit ${PHB_EPOLICY} reporting PHB-EPOLICY" "exit $rc: $out"
fi

echo
echo "== a base policy the program cannot read stops it, rather than the rest going on =="
# The glob has to tell "nothing matched" from "something matched and cannot be read". A name
# the glob found and the program then skipped would build a policy from the bases that
# happened to be readable, which is a narrower sandbox reported as a working one.
UNREADABLE="$WORK/unreadable"
cp -R "$CORE" "$UNREADABLE"
chmod +x "$UNREADABLE"/*.sh
printf '[read]\n/var/tmp\n' > "$UNREADABLE/BaseGood.cfg"
ln -s "$WORK/there-is-no-such-file.cfg" "$UNREADABLE/BaseDangling.cfg"
SPEC3="$(fresh_spec)"
out="$(bash "$UNREADABLE/phobos-policysystem.sh" --spec-dir "$SPEC3" 2>&1)"
rc=$?
if [[ "$rc" -eq "$PHB_EPOLICY" && "$out" == *"PHB-EPOLICY"* ]]; then
  ok "a Base*.cfg that is a broken symbolic link is refused (PHB-EPOLICY)"
else
  bad "a Base*.cfg that is a broken symbolic link is refused (PHB-EPOLICY)" "exit ${PHB_EPOLICY} reporting PHB-EPOLICY" "exit $rc: $out"
fi

ADIRECTORY="$WORK/adirectory"
cp -R "$CORE" "$ADIRECTORY"
chmod +x "$ADIRECTORY"/*.sh
printf '[read]\n/var/tmp\n' > "$ADIRECTORY/BaseGood.cfg"
mkdir -p "$ADIRECTORY/BaseOops.cfg"
SPEC4="$(fresh_spec)"
out="$(bash "$ADIRECTORY/phobos-policysystem.sh" --spec-dir "$SPEC4" 2>&1)"
rc=$?
if [[ "$rc" -eq "$PHB_EPOLICY" && "$out" == *"PHB-EPOLICY"* ]]; then
  ok "a Base*.cfg that is a directory is refused (PHB-EPOLICY)"
else
  bad "a Base*.cfg that is a directory is refused (PHB-EPOLICY)" "exit ${PHB_EPOLICY} reporting PHB-EPOLICY" "exit $rc: $out"
fi

echo
echo "== an unenforceable network rule is refused where the specification is built =="
# The Landlock port rules are built by the filesystem layer, which a run can leave out.
# Judging a rule only there would let a specification carry a port that the connect guard
# drops without a word, so the policy program judges every rule itself, before it writes anything.
refuse_case() {
  local name="$1"
  local body="$2"
  local spec
  local out
  local rc
  spec="$(fresh_spec)"
  printf "%b" "$body" > "$WORK/bad-net.cfg"
  out="$(bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$spec" --config "$WORK/bad-net.cfg" 2>&1)"
  rc=$?
  if [[ "$rc" -eq "$PHB_EPOLICY" && "$out" == *"PHB-EPOLICY"* && ! -f "$spec/net.rules" ]]; then
    ok "$name"
  else
    bad "$name" "exit ${PHB_EPOLICY} reporting PHB-EPOLICY, no net.rules written" "exit $rc: $out"
  fi
}
refuse_case "a [connect] port of 0 is refused"            '[connect]\nallow example.test:0\n'
refuse_case "a [connect] port above 65535 is refused"     '[connect]\nallow example.test:99999\n'
refuse_case "an external host with no port is refused"    '[connect]\nallow example.test\n'
refuse_case "a [bind] port above 65535 is refused"        '[bind]\nallow 99999\n'
# The shell's arithmetic is 64 bits wide and wraps, so a port longer than the protocol has
# digits for must be refused by its shape rather than by its value: 2^64 + 1 evaluates to 1.
refuse_case "a [connect] port of twenty digits is refused" '[connect]\nallow example.test:18446744073709551617\n'
refuse_case "a [connect] port with a leading zero is refused" '[connect]\nallow example.test:08\n'
# Landlock enforces a bind by port and cannot narrow to a local address, so [bind] takes only a
# bare port; a rule that names an address is refused rather than silently widened to any address.
refuse_case "a [bind] rule naming an address is refused"  '[bind]\nallow 127.0.0.1:8080\n'
refuse_case "a [bind] rule naming a bracketed IPv6 address is refused" '[bind]\nallow [::1]:8080\n'

SPEC_OK="$(fresh_spec)"
printf '[connect]\nallow example.test:443\n' > "$WORK/good-net.cfg"
bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$SPEC_OK" --config "$WORK/good-net.cfg" > /dev/null 2>&1
check "a concrete port still builds a specification" "example.test 443" "$(cat "$SPEC_OK/net.rules")"

SPEC_BIND="$(fresh_spec)"
printf '[bind]\nallow 8080\n' > "$WORK/good-bind.cfg"
bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$SPEC_BIND" --config "$WORK/good-bind.cfg" > /dev/null 2>&1
check "a bare [bind] port still builds a specification (host stored as *)" "* 8080" "$(cat "$SPEC_BIND/bind.rules")"

echo
echo "== an unenforceable [accept] rule is refused against the merged policy =="
# The inbound public port must be one the graded code may not bind and the backend one it may,
# judged over the merged [bind] set once every config has been folded in.
refuse_case "an [accept] public port below 1024 is refused"                 '[bind]\nallow 18080\n[accept]\nexpose 80 to 18080 from 1.2.3.4\n'
refuse_case "an [accept] public port that is also a [bind] port is refused" '[bind]\nallow 8080\nallow 18080\n[accept]\nexpose 8080 to 18080 from 1.2.3.4\n'
refuse_case "an [accept] backend port not in [bind] is refused"             '[bind]\nallow 9090\n[accept]\nexpose 8080 to 18080 from 1.2.3.4\n'
refuse_case "an [accept] line of the wrong shape is refused"                '[accept]\nexpose here\n'
refuse_case "an [accept] port with a leading zero is refused"               '[bind]\nallow 18080\n[accept]\nexpose 08080 to 18080 from 1.2.3.4\n'
refuse_case "an [accept] port of twenty digits is refused"                  '[bind]\nallow 18080\n[accept]\nexpose 18446744073709551617 to 18080 from 1.2.3.4\n'
refuse_case "two [accept] rules fronting one port with different backends are refused" '[bind]\nallow 18080\nallow 19090\n[accept]\nexpose 8080 to 18080 from 1.1.1.1\nexpose 8080 to 19090 from 2.2.2.2\n'

SPEC_ACC="$(fresh_spec)"
printf '[bind]\nallow 18080\n[accept]\nexpose 18888 to 18080 from 127.0.0.5, fd00::/8\n' > "$WORK/good-accept.cfg"
bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$SPEC_ACC" --config "$WORK/good-accept.cfg" > /dev/null 2>&1
check "an [accept] rule builds the accept spec"     "18888 18080 127.0.0.5" "$(grep -F '127.0.0.5' "$SPEC_ACC/accept.rules")"
check "an [accept] ipv6 source is carried through"  "18888 18080 fd00::/8"  "$(grep -F 'fd00' "$SPEC_ACC/accept.rules")"

echo
echo "== a single layer runs standalone over a specification phobos-policysystem.sh built =="
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"
mem="$(bash "$CORE_X/phobos-resourcesystem.sh" "$SPEC" -- bash -c 'ulimit -v' 2>/dev/null)"
check "the resource layer applies the built limit (128 MB is 131072 KB)" "131072" "$mem"

finish
