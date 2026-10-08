#!/usr/bin/env bash
# Spike only. Measures what recording costs on two non-interactive workloads: compiling and running
# a Java class (system-call light, JVM start-up heavy), and reading 5000 small files (system-call
# heavy). Each runs three times bare, three times under the recorder's strace with --seccomp-bpf,
# and three times under the same strace without it, and the median wall time of each is printed.
set -euo pipefail

readonly TRACE_SET='%file,%network,%process,ioctl,fchdir,write,setsid,setpgid,io_uring_setup'
readonly WORK=/var/tmp/overhead

mkdir -p "$WORK"
cd "$WORK"
printf 'public class Hello { public static void main(String[] a) { System.out.println("hi"); } }\n' \
  > Hello.java
# find ends with SIGPIPE once head has its 5000 names, which pipefail would report.
{ find /usr -type f -size -64k -print0 || true; } | head -z -n 5000 > files.list

# The two workloads, by name.
workload() {
  case "$1" in
    java) javac Hello.java && java -cp . Hello > /dev/null ;;
    files) xargs -0 cat < files.list > /dev/null ;;
  esac
}

# Prints the median of three wall times, in seconds, of one workload under one wrapper.
median_of_three() {
  local name="$1"
  shift
  local times=()
  local index
  local started
  for index in 1 2 3; do
    started="$EPOCHREALTIME"
    "$@" bash -c "$(declare -f workload); workload ${name}"
    times+=("$(awk -v now="$EPOCHREALTIME" -v then="$started" 'BEGIN { printf "%.3f", now - then }')")
    : "$index"
  done
  printf '%s\n' "${times[@]}" | sort -n | sed -n 2p
}

for name in java files; do
  bare="$(median_of_three "$name" env)"
  bpf="$(median_of_three "$name" strace -f -qq -yy -x -s 4096 --seccomp-bpf -e "trace=${TRACE_SET}" -o "${WORK}/t.bpf")"
  plain="$(median_of_three "$name" strace -f -qq -yy -x -s 4096 -e "trace=${TRACE_SET}" -o "${WORK}/t.plain")"
  printf '%s: bare %ss, strace --seccomp-bpf %ss (x%s), strace without it %ss (x%s), trace %s lines\n' \
    "$name" "$bare" "$bpf" "$(awk -v a="$bpf" -v b="$bare" 'BEGIN { printf "%.1f", a / b }')" \
    "$plain" "$(awk -v a="$plain" -v b="$bare" 'BEGIN { printf "%.1f", a / b }')" \
    "$(wc -l < "${WORK}/t.bpf")"
done
