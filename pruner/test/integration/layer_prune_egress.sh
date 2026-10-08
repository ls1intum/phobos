#!/usr/bin/env bash
# Prunes the fixture exercise with two declared hosts, of which its build needs one, and holds the
# derived [connect] rules to both directions (A.6.5, decision 11).
#
# A declared host is the only external destination the pruner ever grants, and only through a rule
# that names it, which the network layer enforces through the egress broker. A stand-in resolver
# answers every name with 127.0.0.1, where a TLS server stands in for the external host, so the
# whole path runs in a container with no network:
#   permitted  the needed host keeps its rule, and the build reaches it under the derived policy;
#   forbidden  the host the build never asked is dropped from the policy, which the record says. Under
#              the derived policy, with the dropped host made resolvable for the check: on the kept
#              rule's port the connect reaches only the egress broker, which closes it without an
#              answer because the ClientHello names the dropped host; on any other port the guard
#              refuses it with EACCES; and a request aiming at the kept host's address while naming the
#              dropped host gets no answer either;
#   wrong reason  a build that also needs a host nobody declared aborts with "needs external network:
#              undeclared" and writes no policy, although the declared host it needs is there.
#
# Runs inside the prune image with the repository mounted at /repo, read-only, in an ordinary
# container: --network none, cgroup limits, and no --privileged, no --cap-add, no --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../protecter/test/harness.sh
source "${HERE}/../../../protecter/test/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
REPO="$(cd -- "${HERE}/../../.." && pwd)"
HELPERS=/var/tmp/helpers
EXERCISES=/srv/phobos-prune-exercises
KEY=java-egress
DNS_PORT=39470
DNS_SECONDS=3600
SERVER_PORT=8443
STARTUP_SECONDS=20
# A port no rule names, for the guard's refusal of the dropped host.
OTHER_PORT=9443
# An address the dropped host is made to resolve to for the forbidden check (TEST-NET-1, RFC 5737).
UNROUTED_ADDRESS=192.0.2.1
WORK="$(mktemp -d /var/tmp/layer-prune-egress.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }
OUTPUT="${WORK}/out"
CFG="${OUTPUT}/${KEY}_fixture.cfg"

# Stops the stand-ins and removes the working directory however the suite ends.
cleanup() {
  [[ -n "${dns_pid:-}" ]] && kill "${dns_pid}" 2>/dev/null
  [[ -n "${server_pid:-}" ]] && kill "${server_pid}" 2>/dev/null
  rm -rf "${WORK}" "${EXERCISES:?}/${KEY}" "${HELPERS}"
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
  cp -r "${REPO}/pruner/test/integration/layer-prune-fixture" "${EXERCISES}/${KEY}/fixture"
  printf '{"declared_hosts": ["api.example.org:%s", "unused.example.org:%s"]}\n' "${SERVER_PORT}" "${SERVER_PORT}" \
    > "${EXERCISES}/${KEY}/fixture/prune.json"
  cp -r "${REPO}/pruner/src" "${HELPERS}"
  gcc-14 -O2 -o "${WORK}/stubdns" "${REPO}/protecter/test/integration/protection-matrix/stubdns.c" || return 1
  "${WORK}/stubdns" "${DNS_PORT}" "${DNS_SECONDS}" > "${WORK}/dns.log" 2>&1 &
  dns_pid=$!
  openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=api.example.org -days 1 \
    -keyout "${WORK}/key.pem" -out "${WORK}/cert.pem" > "${WORK}/cert.log" 2>&1 || return 1
  openssl s_server -quiet -www -accept "127.0.0.1:${SERVER_PORT}" -cert "${WORK}/cert.pem" -key "${WORK}/key.pem" \
    > "${WORK}/server.log" 2>&1 &
  server_pid=$!
  wait_until_up
}

# Waits, at most STARTUP_SECONDS, until the resolver has said it is up and the server accepts a connection.
wait_until_up() {
  local waited=0
  until grep -q STUB-UP "${WORK}/dns.log" 2>/dev/null && (exec 3<>"/dev/tcp/127.0.0.1/${SERVER_PORT}") 2>/dev/null; do
    (( waited++ < STARTUP_SECONDS * 10 )) || return 1
    sleep 0.1
  done
}

# Prints what the fixture's request to the host $1, naming $2 (by default $1) in its TLS ClientHello,
# answers under the derived policy, with every layer on.
asked_under_policy() {
  local host="$1"
  local named="${2:-$1}"
  local port="${3:-${SERVER_PORT}}"
  "${PHOBOS_HOME}/phobos.sh" --config "${CFG}" --resolver "127.0.0.1:${DNS_PORT}" -- /bin/bash -c \
    "printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client -quiet -connect ${host}:${port} -servername ${named}" \
    2>&1
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
  check "the filesystem was minimised again under the final network rules once a declared host was dropped" "1" \
    "$(python3 -c 'import json, sys; print(sum(entry["stage"] == "filesystem after network minimisation" for entry in json.load(open(sys.argv[1]))["log"]))' "${OUTPUT}/${KEY}_fixture.json")"
  if [[ "$(asked_under_policy api.example.org)" == *"200 ok"* ]]; then
    ok "under the derived policy the build's request reaches the declared host"
  else
    bad "under the derived policy the build's request reaches the declared host" "$(asked_under_policy api.example.org | tail -2)"
  fi
  cp /etc/hosts "${WORK}/hosts.before"
  printf '%s unused.example.org\n' "${UNROUTED_ADDRESS}" >> /etc/hosts
  dropped_answer="$(asked_under_policy unused.example.org)"
  other_port_answer="$(asked_under_policy unused.example.org unused.example.org "${OTHER_PORT}")"
  cat "${WORK}/hosts.before" > /etc/hosts
  if [[ "${dropped_answer}" == *"200 ok"* ]]; then
    bad "on the kept rule's port the egress broker closes a connect to the dropped host unanswered" "it answered"
  elif [[ "${dropped_answer}" == *"unexpected eof"* ]]; then
    ok "on the kept rule's port the egress broker closes a connect to the dropped host unanswered"
  else
    bad "on the kept rule's port the egress broker closes a connect to the dropped host unanswered" \
      "$(tail -3 <<<"${dropped_answer}")"
  fi
  if [[ "${other_port_answer}" == *"errno=13"* ]]; then
    ok "on any other port the guard refuses a connect to the dropped host with EACCES"
  else
    bad "on any other port the guard refuses a connect to the dropped host with EACCES" "$(tail -3 <<<"${other_port_answer}")"
  fi
  named_answer="$(asked_under_policy api.example.org unused.example.org)"
  if [[ "${named_answer}" == *"unexpected eof"* ]]; then
    ok "naming the dropped host while aiming at the kept host's address gets no answer either"
  else
    bad "naming the dropped host while aiming at the kept host's address gets no answer either" "$(tail -3 <<<"${named_answer}")"
  fi
else
  bad "the pruner wrote ${KEY}_fixture.cfg" "$(tail -5 "${WORK}/prune.log")"
fi

undeclared="$(FIXTURE_DECLARED=1 FIXTURE_NEEDS_NET=1 python3 "${HELPERS}/layer_prune/main.py" \
  --resolver "127.0.0.1:${DNS_PORT}" --output-dir "${WORK}/undeclared" "${KEY}" 2>&1)"
status=$?
if [[ "${status}" -ne 0 && "${undeclared}" == *"aborted: needs external network: undeclared 10.0.0.1:80"* \
      && ! -e "${WORK}/undeclared/${KEY}_fixture.cfg" ]]; then
  ok "a build that also needs an undeclared host aborts with \"needs external network: undeclared\" and writes no policy"
else
  bad "a build that also needs an undeclared host aborts with \"needs external network: undeclared\" and writes no policy" \
    "status ${status}: $(tail -3 <<<"${undeclared}")"
fi

finish
