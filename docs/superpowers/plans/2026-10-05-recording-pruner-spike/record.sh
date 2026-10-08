#!/usr/bin/env bash
# Spike only. Records one session of a command under strace, with the terminal passed through.
#
#   record.sh <recording-dir> <session-name> -- <command> [args...]
#
# The first session in a recording directory also writes base-snapshot.txt, the paths that
# existed before anything was recorded, which decides what counts as created by a session.
# strace runs detached (-DDD: a grandchild in a session of its own), so the command stays the
# direct child of the calling shell: job control (Ctrl+Z, fg) and terminal signals (Ctrl+C) reach
# the command exactly as they would without the recorder, and never reach the tracer.
# RECORDER_DETACH=0 runs strace as the parent instead, for the comparison the plan reports.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE

# The calls the recorder reads: every call that names a path, every socket call, the process
# tree, ioctl (a device ioctl no section can grant), fchdir (the working directory), write,
# whose first bytes on a TLS socket carry the server name, and three calls grading always refuses.
readonly TRACE_SET='%file,%network,%process,ioctl,fchdir,write,setsid,setpgid,io_uring_setup'

recording="$1"
session="$2"
shift 2
[[ "${1:-}" == "--" ]] && shift
mkdir -p "${recording}/${session}"
if [[ ! -f "${recording}/base-snapshot.txt" ]]; then
  python3 "${HERE}/recorder.py" snapshot "${recording}/base-snapshot.txt"
fi
printf '%s\n' "$PWD" > "${recording}/${session}/cwd"
detach=(-DDD)
[[ "${RECORDER_DETACH:-1}" == "0" ]] && detach=()
exec strace "${detach[@]}" -f -qq -yy -x -s 4096 --seccomp-bpf -e "trace=${TRACE_SET}" \
  -o "${recording}/${session}/trace" -- "$@"
