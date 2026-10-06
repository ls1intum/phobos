#!/usr/bin/env bash
# Prunes the fixture exercise with two declared hosts, of which its build needs one, and holds the
# derived [connect] rules to both directions (A.6.5, decision 11).
#
# A declared host is the only external destination the pruner ever grants, and only through a rule
# that names it, which the network layer enforces through the egress broker. A stand-in resolver
# answers every name with 127.0.0.1, where a TLS server stands in for the external host, so the
# whole path runs in a container with no network:
#   permitted  the needed host keeps its rule, and the build reaches it under the derived policy;
#   forbidden  the host the build never asked is dropped from the policy, which the record says; under
#              the derived policy a request to it gets no answer, and neither does one that aims at the
#              kept host's address while naming the dropped host in its TLS ClientHello.
#
# Runs inside the prune image with the repository mounted at /repo, read-only, in an ordinary
# container: --network none, cgroup limits, and no --privileged, no --cap-add, no --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
REPO="$(cd -- "${HERE}/../.." && pwd)"
HELPERS=/var/tmp/helpers
EXERCISES=/srv/phobos-prune-exercises
KEY=java-egress
DNS_PORT=39470
DNS_SECONDS=3600
SERVER_PORT=8443
WORK="$(mktemp -d /var/tmp/layer-prune-egress.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }
OUTPUT="${WORK}/out"
CFG="${OUTPUT}/${KEY}_fixture.cfg"

# Stops the stand-ins and removes the working directory however the suite ends.
cleanup() {
  [[ -n "${dns_pid:-}" ]] && kill "${dns_pid}" 2>/dev/null
  [[ -n "${server_pid:-}" ]] && kill "${server_pid}" 2>/dev/null
  rm -rf "${WORK}"
}
trap cleanup EXIT

# Lays out what the fixture reads, the exercise with its two declared hosts, the helpers, the
# stand-in resolver and the TLS server standing in for the external host.
set_up() {
  mkdir -p /srv/prune-fixture/needed /srv/prune-fixture/optional
  printf 'needed\n' > /srv/prune-fixture/needed/data.txt
  printf 'maybe\n' > /srv/prune-fixture/optional/maybe.txt
  rm -rf "${EXERCISES:?}/${KEY}" "${HELPERS}"
  mkdir -p "${EXERCISES}/${KEY}"
  cp -r "${REPO}/tests/integration/layer-prune-fixture" "${EXERCISES}/${KEY}/fixture"
  printf '{"declared_hosts": ["api.example.org:%s", "unused.example.org:%s"]}\n' "${SERVER_PORT}" "${SERVER_PORT}" \
    > "${EXERCISES}/${KEY}/fixture/prune.json"
  cp -r "${REPO}/var/tmp/helpers" "${HELPERS}"
  gcc-14 -O2 -o "${WORK}/stubdns" "${REPO}/tests/integration/protection-matrix/stubdns.c" || return 1
  "${WORK}/stubdns" "${DNS_PORT}" "${DNS_SECONDS}" > "${WORK}/dns.log" 2>&1 &
  dns_pid=$!
  openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=api.example.org -days 1 \
    -keyout "${WORK}/key.pem" -out "${WORK}/cert.pem" > "${WORK}/cert.log" 2>&1 || return 1
  openssl s_server -quiet -www -accept "127.0.0.1:${SERVER_PORT}" -cert "${WORK}/cert.pem" -key "${WORK}/key.pem" \
    > "${WORK}/server.log" 2>&1 &
  server_pid=$!
  sleep 1
}

# Prints what the fixture's request to the host $1, naming $2 (by default $1) in its TLS ClientHello,
# answers under the derived policy, with every layer on.
asked_under_policy() {
  local host="$1"
  local named="${2:-$1}"
  "${PHOBOS_HOME}/phobos.sh" --config "${CFG}" --resolver "127.0.0.1:${DNS_PORT}" -- /bin/bash -c \
    "printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client -quiet -connect ${host}:${SERVER_PORT} -servername ${named}" \
    2>/dev/null
}

if ! set_up; then
  bad "the stand-in resolver and the TLS server start" "$(cat "${WORK}"/*.log 2>/dev/null | tail -5)"
  finish
fi

FIXTURE_DECLARED=1 python3 "${HELPERS}/layer_prune/main.py" --resolver "127.0.0.1:${DNS_PORT}" \
  --output-dir "${OUTPUT}" "${KEY}" > "${WORK}/prune.log" 2>&1
status=$?
check "the pruner ends with status 0 on the fixture with two declared hosts" "0" "${status}"
[[ "${status}" -eq 0 ]] || sed 's/^/    /' "${WORK}/prune.log" | tail -20

if [[ -f "${CFG}" ]]; then
  check "the needed declared host keeps exactly its rule" "allow api.example.org:${SERVER_PORT}" \
    "$(grep -x "allow api.example.org:${SERVER_PORT}" "${CFG}")"
  check "the declared host the build never asked is dropped from the policy" "" "$(grep 'unused.example.org' "${CFG}")"
  dropped="$(python3 - "${OUTPUT}/${KEY}_fixture.json" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1]))
minimised = [entry for entry in record["log"] if entry["stage"] == "network minimisation"][-1]
kept = {rule for kind, rule in minimised["kept"]}
print(sorted(rule for kind, rule in minimised["before"] if rule not in kept))
PY
)"
  check "the record lists the unused declared host among the rules the minimisation removed" \
    "['allow unused.example.org:${SERVER_PORT}']" "${dropped}"
  if [[ "$(asked_under_policy api.example.org)" == *"200 ok"* ]]; then
    ok "under the derived policy the build's request reaches the declared host"
  else
    bad "under the derived policy the build's request reaches the declared host" "$(asked_under_policy api.example.org | tail -2)"
  fi
  if [[ "$(asked_under_policy unused.example.org)" == *"200 ok"* ]]; then
    bad "under the derived policy the dropped host gets no answer" "it answered"
  else
    ok "under the derived policy the dropped host gets no answer"
  fi
  if [[ "$(asked_under_policy api.example.org unused.example.org)" == *"200 ok"* ]]; then
    bad "naming the dropped host while aiming at the kept host's address gets no answer either" "it answered"
  else
    ok "naming the dropped host while aiming at the kept host's address gets no answer either"
  fi
else
  bad "the pruner wrote ${KEY}_fixture.cfg" "$(tail -5 "${WORK}/prune.log")"
fi

finish
