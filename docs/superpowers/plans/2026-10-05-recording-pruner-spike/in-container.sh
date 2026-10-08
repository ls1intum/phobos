#!/usr/bin/env bash
# Spike only. The container side of run-spike.sh, one mode per fresh container.
#
#   in-container.sh bare     <out-dir> [--network]   the session without any observer
#   in-container.sh record   <out-dir> [--network]   the session under the recorder, then generate
#   in-container.sh attached <out-dir> [--network]   as record, strace as the parent (no -DDD)
#   in-container.sh replay   <out-dir> [--network]   the session under phobos.sh with the policy
#
# The replay replaces the image's base policy with an empty one, so the generated configuration
# alone has to carry the session, and adds a one-line overlay that switches the timeout off: GNU
# timeout puts the command in a process group of its own, which is never the terminal's foreground
# group, so an interactive command under it is stopped by SIGTTIN on its first read.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE

# Prints the seconds since the given $EPOCHREALTIME value, to two decimals.
seconds_since() {
  awk -v now="$EPOCHREALTIME" -v then="$1" 'BEGIN { printf "%.2f", now - then }'
}

mode="$1"
out="$2"
network="${3:-}"
mkdir -p "$out"
bash "${HERE}/prepare.sh"
cd /var/tmp/testing-dir

case "$mode" in
  bare)
    python3 "${HERE}/drive_session.py" ${network:+--network} --transcript "${out}/bare.txt" \
      --launcher "python3 -q" | tee "${out}/bare.json"
    ;;
  record|attached)
    detach=1
    [[ "$mode" == "attached" ]] && detach=0
    started="$EPOCHREALTIME"
    RECORDER_DETACH="$detach" python3 "${HERE}/drive_session.py" ${network:+--network} \
      --transcript "${out}/${mode}.txt" \
      --launcher "RECORDER_DETACH=${detach} ${HERE}/record.sh ${out} ${mode} -- python3 -q" \
      | tee "${out}/${mode}.json"
    while pgrep -x strace > /dev/null; do sleep 0.2; done
    printf 'session plus tracer exit: %s s\n' "$(seconds_since "$started")"
    snapshot_started="$EPOCHREALTIME"
    python3 "${HERE}/recorder.py" snapshot /dev/null
    printf 'snapshot of this filesystem: %s s, %s paths\n' \
      "$(seconds_since "$snapshot_started")" "$(wc -l < "${out}/base-snapshot.txt")"
    printf 'trace: %s lines, %s bytes\n' "$(wc -l < "${out}/${mode}/trace")" "$(wc -c < "${out}/${mode}/trace")"
    python3 "${HERE}/recorder.py" generate --snapshot "${out}/base-snapshot.txt" \
      --trace "${out}/${mode}/trace" --cwd /var/tmp/testing-dir --out "${out}/generated.cfg"
    ;;
  replay)
    rm -f "${PHOBOS_HOME}"/Base*.cfg
    printf '# Empty for the replay: the generated configuration alone must carry the session.\n' \
      > "${PHOBOS_HOME}/BaseReplay.cfg"
    printf '[limits]\ntimeout=0\n' > /var/tmp/interactive-replay.cfg
    spec="$(mktemp -d /var/tmp/phobos-spec-check.XXXXXX)"
    "${PHOBOS_HOME}/phobos-policysystem.sh" --spec-dir "$spec" --config "${out}/generated.cfg" \
      --tail-flags-file "${PHOBOS_HOME}/TailPhobos.cfg" > "${out}/policysystem.txt" 2>&1
    printf 'phobos-policysystem.sh accepted the generated configuration\n'
    resolver=""
    if [[ -n "$network" ]]; then
      resolver="--resolver $(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)"
    fi
    python3 "${HERE}/drive_session.py" ${network:+--network} --transcript "${out}/replay.txt" \
      --launcher "strace -DDD -f -qq -yy -o ${out}/replay-trace ${PHOBOS_HOME}/phobos.sh ${resolver} --config ${out}/generated.cfg --config /var/tmp/interactive-replay.cfg -- python3 -q" \
      | tee "${out}/replay.json" || true
    while pgrep -x strace > /dev/null; do sleep 0.2; done
    python3 "${HERE}/recorder.py" denials --recorded "${out}/record/trace" \
      "${out}/replay-trace" | tee "${out}/replay-denials.txt" || true
    bash "${HERE}/prepare.sh"
    cp "${HERE}/containment.py" /var/tmp/testing-dir/containment.py
    # The resolver is empty or an option and its value, which must split into two words.
    # shellcheck disable=SC2086
    "${PHOBOS_HOME}/phobos.sh" ${resolver} --config "${out}/generated.cfg" \
      --config /var/tmp/interactive-replay.cfg -- python3 /var/tmp/testing-dir/containment.py \
      2>/dev/null | tee "${out}/containment.txt"
    ;;
  *)
    printf 'unknown mode %s\n' "$mode" >&2
    exit 2
    ;;
esac
