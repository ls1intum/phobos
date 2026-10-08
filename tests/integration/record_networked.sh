#!/usr/bin/env bash
# Holds the recording pruner to what it promises for a host name, on a Docker network with no route out.
#
# A stand-in server (record-network-server/serve.py) answers DNS for api.phobos.test and serves TLS for
# it on 443 and plain text on 8443, in a container of the prune image on a network created with
# --internal. A session in a second container on that network makes an HTTPS request to the name, and
# generate must write `allow api.phobos.test:443` from the TLS host name, say that the policy needs
# --resolver, and leave the lookup of the resolver as a comment. The replay, in a third container,
# runs under phobos.sh with --resolver pointing at the server: no regression, and the request works. In
# a fourth, the forbidden direction: a connection to the server's address or the name on the port the
# policy does not name is refused. Every container is ordinary: no --privileged, --cap-add or
# --security-opt; the network is the only thing that is not --network none, and it has no route out.
#
#   record_networked.sh <prune image>
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PRUNE_IMAGE="${1:?usage: record_networked.sh <prune image>}"
REPOSITORY="$(cd -- "${HERE}/../.." && pwd)"
# Names of this run's own, so parallel runs never share a network, a volume or a container.
RUN_ID="record-net-$$-${RANDOM}"
NETWORK="${RUN_ID}-net"
SERVER="${RUN_ID}-server"
VOLUME="${RUN_ID}-recordings"
WORK="$(mktemp -d)"
SERVER_IP=""

# Removes what this run created, and only that.
cleanup() {
  docker rm -f "${SERVER}" > /dev/null 2>&1 || true
  docker network rm "${NETWORK}" > /dev/null 2>&1 || true
  docker volume rm -f "${VOLUME}" > /dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

# Runs a command in a new ordinary container of the prune image on the internal network, with the
# stand-in server as its resolver, and prints what it printed. Takes the entry point, then its arguments.
in_network() {
  local entrypoint="$1"
  shift
  docker run --rm --name "${RUN_ID}-${RANDOM}" --network "${NETWORK}" --dns "${SERVER_IP}" \
    -v "${REPOSITORY}/tests:/tests:ro" \
    -v "${REPOSITORY}/var/tmp/helpers:/var/tmp/helpers:ro" \
    -v "${REPOSITORY}/core:/repo-core:ro" \
    -v "${VOLUME}:/var/tmp/recordings" \
    --entrypoint "${entrypoint}" "${PRUNE_IMAGE}" "$@"
}

RECORDER=/var/tmp/helpers/layer_record/phobos-record
SCRIPT=/tests/integration/record-fixture/network.script
SESSION=(env HOME=/var/tmp/testing-dir python3 -q)

# Starts the stand-in server and waits until it says it serves; leaves its address in SERVER_IP.
start_server() {
  docker run -d --name "${SERVER}" --network "${NETWORK}" \
    -v "${HERE}/record-network-server/serve.py:/serve.py:ro" \
    --entrypoint python3 "${PRUNE_IMAGE}" /serve.py > /dev/null || return 1
  local waited=0
  until grep -q '^serving ' <<<"$(docker logs "${SERVER}" 2>&1)"; do
    sleep 1
    waited=$((waited + 1))
    if (( waited > 30 )); then
      echo "the stand-in server did not start: $(docker logs "${SERVER}" 2>&1 | tail -5)" >&2
      return 1
    fi
  done
  SERVER_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}" "${SERVER}")"
}

docker network create --internal "${NETWORK}" > /dev/null || { echo "cannot create the network ${NETWORK}" >&2; exit 1; }
docker volume create "${VOLUME}" > /dev/null || { echo "cannot create the volume ${VOLUME}" >&2; exit 1; }
start_server || { bad "the stand-in server starts"; finish; exit 1; }
check "the network has no route out" true "$(docker network inspect -f '{{.Internal}}' "${NETWORK}")"
ok "the stand-in server runs at ${SERVER_IP}"

in_network "${RECORDER}" record --name net --script "${SCRIPT}" -- "${SESSION[@]}" < /dev/null > "${WORK}/record.out" 2>&1
check "the HTTPS session is recorded with Python's own status" 0 "$?"
in_network "${RECORDER}" generate --name net < /dev/null > "${WORK}/generate.out" 2>&1
status=$?
check "generate answers 0" 0 "${status}"
if [[ "${status}" != 0 ]]; then
  cat "${WORK}/generate.out"
fi
in_network cat /var/tmp/recordings/net/policy.cfg > "${WORK}/policy.cfg"

if grep -qxF "allow api.phobos.test:443" "${WORK}/policy.cfg"; then
  ok "the TLS host name becomes allow api.phobos.test:443"
else
  bad "the TLS host name becomes allow api.phobos.test:443" "$(cat "${WORK}/policy.cfg" "${WORK}/generate.out")"
fi
if grep -qF "This policy needs --resolver" "${WORK}/policy.cfg"; then
  ok "the header says the policy needs --resolver"
else
  bad "the header says the policy needs --resolver" "$(head -12 "${WORK}/policy.cfg")"
fi
if grep -v '^#' "${WORK}/policy.cfg" | grep -qE ':53( udp)?$'; then
  bad "no rule names port 53 uncommented" "$(grep -E ':53' "${WORK}/policy.cfg")"
else
  ok "no rule names port 53 uncommented: the network layer maps the name, so the lookup is a comment at most"
fi
if grep -qF "${SERVER_IP}:8443" "${WORK}/policy.cfg"; then
  bad "no rule names the plain port, which the session never used" "$(grep -F 8443 "${WORK}/policy.cfg")"
else
  ok "no rule names the plain port, which the session never used"
fi

in_network "${RECORDER}" check --name net --resolver "${SERVER_IP}" --script "${SCRIPT}" -- "${SESSION[@]}" \
  < /dev/null > "${WORK}/check.out" 2>&1
status=$?
check "the replay under phobos.sh with --resolver passes in a new container" 0 "${status}"
if [[ "${status}" != 0 ]]; then
  tail -30 "${WORK}/check.out"
fi
in_network sh -c 'cat /var/tmp/recordings/net/check-*/check.json' > "${WORK}/check.json" 2>&1
if python3 - "${WORK}/check.json" <<'PYTHON'
import json
import sys

report = json.load(open(sys.argv[1]))
assert report["regressions"] == [], report["regressions"]
assert report["not_completed"] == [], report["not_completed"]
assert report["mode"] == "fresh-container", report["mode"]
PYTHON
then
  ok "the replay found no regression, ran the session and was in a fresh container"
else
  bad "the replay found no regression, ran the session and was in a fresh container" "$(tail -20 "${WORK}/check.out")"
fi

# The forbidden direction, under the generated policy: the server's address and the name on a port the
# policy does not name are refused, and the recorded request still works.
forbidden() {
  local title="$1"
  local target="$2"
  local answer
  answer="$(in_network sh -c 'mkdir -p /var/tmp/testing-dir; exec "$@"' sh /var/tmp/opt/core/phobos.sh \
    --resolver "${SERVER_IP}" --config /var/tmp/recordings/net/policy.cfg -- \
    python3 -c "import socket; socket.create_connection(('${target}', 8443), timeout=3)" 2>&1 < /dev/null)"
  if grep -q 'PermissionError: \[Errno 13\]' <<<"${answer}"; then
    ok "${title}"
  else
    bad "${title}" "${answer}"
  fi
}
forbidden "a connection to the server's address on the port the policy does not name is refused" "${SERVER_IP}"
forbidden "a connection to the recorded name on the port the policy does not name is refused" "api.phobos.test"

finish
