#!/usr/bin/env bash
# Holds the prune image to what the layer pruner's observer relies on, in both directions.
#
# The layer pruner runs the reference exercise through the shipped phobos.sh chain under strace,
# an unprivileged ptrace observer, and grants only what a recorded refusal proves necessary.
# That rests on three facts about the prune image, checked here: its base grants nothing and
# phobos-policysystem.sh still accepts it, strace records a Landlock refusal made inside the
# chain with its path and errno while a permitted read beside it succeeds, and the parser and
# attribution turn that record into exactly one filesystem denial and none for the permitted read.
# A fourth fact is about what the pruner writes: every policy cfgfile.render produces is accepted by
# the real parser and runs a command, and the strict subset it refuses is one Phobos refuses too.
#
# Runs inside the prune image (docker/prune_phase/layers/Dockerfile) with tests/ mounted at
# /tests and var/tmp/helpers at /var/tmp/helpers, both read-only, in an ordinary container:
# --network none, and no --privileged, no --cap-add, no --security-opt. ptrace of one's own child
# needs none of them.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
# Where the pruner's Python package is mounted in the prune container, read-only (A.6.1).
HELPERS="${LAYER_PRUNE_HELPERS:-/var/tmp/helpers}"
WORK="$(mktemp -d /var/tmp/phobos-prune-observer.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }
FIXTURE_CFG="${WORK}/fixture.cfg"
# The permitted neighbour of the refused read: a file under /usr that every Ubuntu image carries.
PERMITTED_FILE=/usr/share/common-licenses/GPL-3
# The refused read: /etc/hostname, which the fixture configuration does not name.
FORBIDDEN_FILE=/etc/hostname

# Removes the working directory however the suite ends.
cleanup() {
  rm -rf "${WORK}"
}
trap cleanup EXIT

# Writes the fixture configuration: read and execute on the system directories a dynamically
# linked cat needs to start, and nothing else, so /etc/hostname is the one path it is refused.
write_fixture_cfg() {
  local directory
  {
    printf '[read]\n'
    for directory in /usr /lib /bin /lib64; do
      [[ -e "${directory}" ]] && printf '%s\n' "${directory}"
    done
    printf '\n[execute]\n'
    for directory in /usr /lib /bin /lib64; do
      [[ -e "${directory}" ]] && printf '%s\n' "${directory}"
    done
  } >"${FIXTURE_CFG}"
}

# The prune image ships BasePrune.cfg as its only base, and the run-phase image's language base
# is gone, so the pruner starts from nothing.
check_only_the_prune_base_is_shipped() {
  local bases
  bases="$(cd "${PHOBOS_HOME}" && printf '%s ' Base*.cfg)"
  check "the prune image ships BasePrune.cfg as its only base" "BasePrune.cfg " "${bases}"
}

# The base the prune image ships must grant nothing beyond what a run cannot start without, and
# phobos-policysystem.sh must accept it.
check_empty_base_is_accepted() {
  local spec
  spec="$(mktemp -d /var/tmp/phobos-spec-check.XXXXXX)"
  if "${PHOBOS_HOME}/phobos-policysystem.sh" --spec-dir "${spec}" --tail-flags-file "${PHOBOS_HOME}/TailPhobos.cfg" >"${WORK}/policy.log" 2>&1; then
    ok "the prune base is accepted by the policy parser"
  else
    bad "the prune base is accepted by the policy parser" "$(tail -3 "${WORK}/policy.log")"
  fi
  local granted
  granted="$(cat "${spec}"/*.paths "${spec}"/*.rules 2>/dev/null | grep -c .)"
  check "the prune base grants no path and no network rule" "0" "${granted}"
  rm -rf "${spec}"
}

# strace and python3 are what the prune image adds to the run-phase image.
check_the_observer_is_installed() {
  local tool
  for tool in strace python3; do
    if command -v "${tool}" >/dev/null 2>&1; then
      ok "${tool} is installed in the prune image"
    else
      bad "${tool} is installed in the prune image"
    fi
  done
}

# Prints a strace -f log with every "<unfinished ...>" half joined to its "<... resumed>" half, so a
# call another thread's line interrupted can be matched on one line. Written in awk rather than
# with the pruner's parser, so that a parser defect cannot hide an observer that saw nothing.
joined_trace() {
  awk '
    match($0, /^[0-9]+ +/) { pid = substr($0, 1, RLENGTH); sub(/ +$/, "", pid) }
    / <unfinished \.\.\.>$/ { head[pid] = $0; sub(/ <unfinished \.\.\.>$/, "", head[pid]); next }
    /^[0-9]+ +<\.\.\. [a-z0-9_]+ resumed>/ {
      tail = $0
      sub(/^[0-9]+ +<\.\.\. [a-z0-9_]+ resumed>/, "", tail)
      print head[pid] tail
      delete head[pid]
      next
    }
    { print }
  ' "$1"
}

# Runs one command through the whole phobos.sh chain under strace, with the fixture
# configuration, writing the trace to the file named by $1 and the command's output to $2. The
# options are those of strace_parse.STRACE_ARGUMENTS, spelt out so the check needs no Python.
traced_run() {
  local trace="$1"
  local output="$2"
  shift 2
  strace -f -qq -y -s 4096 -o "${trace}" \
    -e trace=%file,%network,%process,%desc,landlock_restrict_self,setsid,setpgid,ioctl \
    "${PHOBOS_HOME}/phobos.sh" --config "${FIXTURE_CFG}" -- "$@" >"${output}" 2>&1
}

# Under the prune base a read of /etc/hostname is refused, and strace records that refusal with
# its path and errno.
check_strace_sees_a_landlock_refusal() {
  local trace="${WORK}/forbidden.trace"
  traced_run "${trace}" "${WORK}/forbidden.out" /bin/cat "${FORBIDDEN_FILE}"
  local joined
  joined="$(joined_trace "${trace}" 2>/dev/null)"
  if grep -q "openat(.*\"${FORBIDDEN_FILE}\".*= -1 EACCES" <<<"${joined}"; then
    ok "strace records the Landlock refusal of ${FORBIDDEN_FILE}"
  else
    bad "strace records the Landlock refusal of ${FORBIDDEN_FILE}" "$(tail -3 "${WORK}/forbidden.out")"
  fi
  if grep -q 'landlock_restrict_self(.*) = 0' <<<"${joined}"; then
    ok "strace records the chain applying Landlock"
  else
    bad "strace records the chain applying Landlock" "$(tail -3 "${WORK}/forbidden.out")"
  fi
}

# The permitted neighbour, under the same configuration and the same observer, is read and its
# content reaches the output, so the observer does not stop what the policy permits.
check_a_permitted_read_still_works_under_strace() {
  local trace="${WORK}/permitted.trace"
  traced_run "${trace}" "${WORK}/permitted.out" /bin/cat "${PERMITTED_FILE}"
  if grep -q 'GNU GENERAL PUBLIC LICENSE' "${WORK}/permitted.out"; then
    ok "a file the configuration grants is read under strace"
  else
    bad "a file the configuration grants is read under strace" "$(tail -3 "${WORK}/permitted.out")"
  fi
  local joined
  joined="$(joined_trace "${trace}" 2>/dev/null)"
  if grep -q "openat(.*\"${PERMITTED_FILE}\".*= [0-9]" <<<"${joined}" \
    && ! grep -q "openat(.*\"${PERMITTED_FILE}\".*= -1 E" <<<"${joined}"; then
    ok "strace records the permitted file opened and never refused"
  else
    bad "strace records the permitted file opened and never refused" "$(grep "${PERMITTED_FILE}" <<<"${joined}" | head -1)"
  fi
}

# Prints what the pruner's parser and attribution make of the trace named by $1, one line each:
# the filesystem denials naming /etc/hostname with their sections and whether the control replay
# confirms them as Landlock's, and the paths of filesystem denials that resolve into /usr, which
# the fixture configuration grants. Assumes the helpers are mounted at ${HELPERS}.
attribution_summary() {
  HELPERS="${HELPERS}" python3 - "$1" <<'PY'
import os
import sys

sys.path.insert(0, os.environ["HELPERS"])

from layer_prune import attribute
from layer_prune import control
from layer_prune import strace_parse

with open(sys.argv[1], encoding="utf-8", errors="surrogateescape") as log:
    trace = strace_parse.parse_trace(log)
found = [denial for denial in attribute.denials(trace, "/var/tmp/testing-dir") if denial.layer == "filesystem"]
hostname = [denial for denial in found if denial.objects == ("/etc/hostname",)]
sections = " ".join(sorted(section for denial in hostname for section in denial.sections))
print("hostname", len(hostname), sections, all(control.landlock_caused(denial) for denial in hostname))
granted = [path for denial in found for path in denial.objects
           if os.path.realpath(path) == "/usr" or os.path.realpath(path).startswith("/usr/")]
print("granted", len(granted), " ".join(granted))
PY
}

# The forbidden direction through the parser and attribution: the refused read of /etc/hostname
# becomes exactly one filesystem denial asking for read, which the control replay confirms, and
# nothing the configuration grants is reported refused.
check_attribution_of_the_refusal() {
  local summary
  summary="$(attribution_summary "${WORK}/forbidden.trace" 2>&1)"
  check "the refusal of ${FORBIDDEN_FILE} is one filesystem denial asking for read, confirmed as Landlock's" \
    "hostname 1 read True" "$(grep '^hostname' <<<"${summary}" || printf '%s' "${summary}")"
  check "no filesystem denial of that run names a path the configuration grants" \
    "granted 0 " "$(grep '^granted' <<<"${summary}" || printf '%s' "${summary}")"
}

# The permitted direction through the parser and attribution: a run that only reads what the
# configuration grants yields no denial for /etc/hostname and none for anything under /usr.
check_attribution_of_the_permitted_run() {
  local summary
  summary="$(attribution_summary "${WORK}/permitted.trace" 2>&1)"
  check "a run reading only granted files yields no denial for ${FORBIDDEN_FILE}" \
    "hostname 0  True" "$(grep '^hostname' <<<"${summary}" || printf '%s' "${summary}")"
  check "a run reading only granted files yields no denial under /usr" \
    "granted 0 " "$(grep '^granted' <<<"${summary}" || printf '%s' "${summary}")"
}

# Writes into the file named by $2 what cfgfile.render makes of the policy named by $1: "permissive",
# the permissive policy of this image's own root; "small", a policy with every filesystem section, a
# comment, network rules and limits; "commented", the same with a header, trailing notes, rule
# comments and a comment rule, some holding what would end a line if written unescaped; or "subset", a
# nested strict subset, which render must refuse, in which case it writes "refused" instead. Assumes the
# helpers are mounted at ${HELPERS}.
rendered_policy() {
  HELPERS="${HELPERS}" python3 - "$1" >"$2" 2>"$2.err" <<'PY'
import os
import pathlib
import sys

sys.path.insert(0, os.environ["HELPERS"])

from layer_prune import cfgfile

small = cfgfile.Policy(
    fs={"/usr": frozenset({"read", "execute"}), "/var/tmp/testing-dir": frozenset(cfgfile.WRITE_SECTIONS),
        "/dev/null": frozenset({"read", "write"}), "/proc": frozenset({"read"})},
    connect=("allow 127.0.0.1:*", "allow 127.0.0.2:*", "allow [::1]", "allow localhost udp"),
    bind=("allow 0", "allow 0 udp"),
    limits={"timeout": 60, "cpu": 30, "nproc": 64, "nofile": 256, "fsize_mb": 16},
    comments={"/proc": "per-run name: /proc/<pid>/status, observed as /proc/7/status; granted on /proc"})
subset = cfgfile.Policy(fs={"/usr": frozenset({"read", "execute"}), "/usr/bin": frozenset({"read"})},
                        connect=(), bind=(), limits={})
commented = cfgfile.Policy(
    fs=small.fs,
    connect=(cfgfile.Rule("allow 127.0.0.1:*", "seen as evil\n[write]\n/"), cfgfile.Rule("# not granted: allow x:53 udp")),
    bind=(cfgfile.Rule("allow 0", "a comment above a rule"),), limits={},
    header=("Recorded by a test.", "a header\r\n[read]\n/"), notes=("a trailing note\u2028[write]",))
policies = {"permissive": cfgfile.permissive_policy(pathlib.Path("/")), "small": small, "commented": commented,
            "subset": subset}
try:
    sys.stdout.write(cfgfile.render(policies[sys.argv[1]]))
except ValueError:
    sys.stdout.write("refused\n")
PY
}

# The renderer and the real parser agree in both directions: every policy render writes is accepted
# by phobos-policysystem.sh and runs a command through the whole phobos.sh chain, and the nested strict
# subset that render refuses is the one the filesystem layer refuses at run time with PHB-EPOLICY.
check_rendered_policies_meet_the_parser() {
  local name
  local spec
  local status
  for name in permissive small commented; do
    rendered_policy "${name}" "${WORK}/${name}.cfg"
    spec="$(mktemp -d /var/tmp/phobos-spec-check.XXXXXX)" || { bad "a specification directory can be made"; continue; }
    "${PHOBOS_HOME}/phobos-policysystem.sh" --spec-dir "${spec}" --config "${WORK}/${name}.cfg" >"${WORK}/${name}.log" 2>&1
    status=$?
    rm -rf "${spec}"
    check "the ${name} policy render writes is accepted by phobos-policysystem.sh" "0" "${status}"
    "${PHOBOS_HOME}/phobos.sh" --config "${WORK}/${name}.cfg" -- /bin/true >"${WORK}/${name}-run.log" 2>&1
    check "a command runs under the ${name} policy through phobos.sh" "0" "$?"
  done
  check "what would end a line in the commented policy's comments is escaped: it has exactly the sections it was given" \
    "[bind] [connect] [create-ipc] [create-symlink] [create] [delete] [execute] [read] [restructure] [write]" \
    "$(grep '^\[' "${WORK}/commented.cfg" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
  check "and holds no carriage return or line separator" 0 "$(grep -c -e $'\r' -e $'\xe2\x80\xa8' "${WORK}/commented.cfg")"
  rendered_policy subset "${WORK}/subset.out"
  check "render refuses a nested strict subset" "refused" "$(cat "${WORK}/subset.out")"
  printf '[read]\n/usr\n/usr/bin\n\n[execute]\n/usr\n' >"${WORK}/subset.cfg"
  "${PHOBOS_HOME}/phobos.sh" --config "${WORK}/subset.cfg" -- /bin/true >"${WORK}/subset-run.log" 2>&1
  status=$?
  if [[ "${status}" -eq 11 ]] && grep -q 'PHB-EPOLICY' "${WORK}/subset-run.log"; then
    ok "phobos.sh refuses the same nested strict subset with PHB-EPOLICY"
  else
    bad "phobos.sh refuses the same nested strict subset with PHB-EPOLICY" "status ${status}: $(tail -2 "${WORK}/subset-run.log")"
  fi
}

check_only_the_prune_base_is_shipped
check_empty_base_is_accepted
check_the_observer_is_installed
mkdir -p /var/tmp/testing-dir
write_fixture_cfg
check_strace_sees_a_landlock_refusal
check_a_permitted_read_still_works_under_strace
check_attribution_of_the_refusal
check_attribution_of_the_permitted_run
check_rendered_policies_meet_the_parser
finish
