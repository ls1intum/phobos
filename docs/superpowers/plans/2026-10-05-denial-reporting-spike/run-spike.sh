#!/usr/bin/env bash
# Measures the denial-reporting spike inside the run-phase image. Not part of Phobos.
#
# Run from the repository root, in an ordinary container (no --privileged, no --cap-add, no
# --security-opt), with this folder mounted read-only at /spike:
#
#   docker run --rm --network none \
#     -v "$PWD/docs/superpowers/plans/2026-10-05-denial-reporting-spike:/spike:ro" \
#     phobos-run-phase:ci bash /spike/run-spike.sh
#
# It prints one line per measurement: the workload, the mode, the repetition and the seconds.
set -euo pipefail

# How often each workload runs in each mode, the modes interleaved so drift spreads evenly.
readonly REPETITIONS="${REPETITIONS:-5}"
# How many open, read and close rounds the file loop makes.
readonly ROUNDS="${ROUNDS:-200000}"
# How many classes the javac workload compiles.
readonly CLASSES="${CLASSES:-300}"
# A mode ending in +sync asks the kernel to wake the supervisor synchronously (Linux 6.6).
readonly MODES=(plain landlock trap trap+sync report report+sync)

# The binaries go under /usr/local/bin, which the rules below make executable.
cd /tmp
gcc-14 -std=gnu23 -O2 -Wall -Wextra -Werror -o /usr/local/bin/spike /spike/denial-report-spike.c
gcc-14 -std=gnu23 -O2 -Wall -Wextra -Werror -o /usr/local/bin/fileloop /spike/fileloop.c
mkdir -p /tmp/work
echo payload > /tmp/work/allowed

# The rules every measured run gets, roughly the shape of the shipped Java policy: the system
# read-only and executable, /dev/urandom readable, /tmp, /dev/null and the Maven repository
# writable. /proc and /sys stay unnamed, as they are in the shipped policy.
rules=(--read /usr --read /lib --read /bin --read /etc --read /opt --read /dev/urandom
       --read /dev/random --write /tmp --write /root/.m2 --write /dev/null)
# The denied file lives under /var/tmp, which no rule names.
mkdir -p /var/tmp/denied
echo payload > /var/tmp/denied/secret

# Runs one command in one mode and prints the wall-clock seconds.
measure() {
  local label="$1"
  local mode="$2"
  local repetition="$3"
  shift 3
  local start
  local end
  local status=0
  local flags=(--mode "${mode%+sync}")
  if [[ "$mode" == *+sync ]]; then flags+=(--sync-wakeup); fi
  start="$(date +%s.%N)"
  spike "${flags[@]}" "${rules[@]}" -- "$@" > "/tmp/out.${label}.${mode}" 2> "/tmp/err.${label}.${mode}" || status=$?
  end="$(date +%s.%N)"
  awk -v l="$label" -v m="$mode" -v r="$repetition" -v s="$start" -v e="$end" -v c="$status" \
    'BEGIN { printf "%s %s %s %.3f status=%d\n", l, m, r, e - s, c }'
}

# The javac workload: CLASSES small classes that call each other.
mkdir -p /tmp/work/javac/src /tmp/work/javac/out
for ((i = 0; i < CLASSES; i++)); do
  printf 'public class C%d { public static int f(int x) { return x + %d; } }\n' "$i" "$i" \
    > "/tmp/work/javac/src/C${i}.java"
done

# The Maven workload: a small project with ten JUnit 5 test classes, built offline from the
# repository the image already carries.
mkdir -p /tmp/work/mvn/src/main/java/demo /tmp/work/mvn/src/test/java/demo
cat > /tmp/work/mvn/pom.xml <<'POM'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId>
  <artifactId>demo</artifactId>
  <version>1</version>
  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.13.4</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin><artifactId>maven-compiler-plugin</artifactId><version>3.14.0</version></plugin>
      <plugin><artifactId>maven-resources-plugin</artifactId><version>3.3.1</version></plugin>
      <plugin><artifactId>maven-surefire-plugin</artifactId><version>3.5.3</version></plugin>
    </plugins>
  </build>
</project>
POM
for ((i = 0; i < 10; i++)); do
  printf 'package demo; public class M%d { public static int f(int x) { return x * %d; } }\n' "$i" "$i" \
    > "/tmp/work/mvn/src/main/java/demo/M${i}.java"
  printf 'package demo; import org.junit.jupiter.api.Test; import static org.junit.jupiter.api.Assertions.assertEquals; public class M%dTest { @Test void f() { assertEquals(%d, M%d.f(1)); } }\n' "$i" "$i" "$i" \
    > "/tmp/work/mvn/src/test/java/demo/M${i}Test.java"
done

for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
  for mode in "${MODES[@]}"; do
    measure fileloop-allowed "$mode" "$repetition" fileloop /tmp/work/allowed "$ROUNDS"
    sed -n 's/.* refused=\([0-9]*\) ns_per_round=\([0-9]*\).*/fileloop-allowed-ns-per-round '"$mode $repetition"' \2 refused=\1/p' "/tmp/out.fileloop-allowed.${mode}"
    measure fileloop-denied "$mode" "$repetition" fileloop /var/tmp/denied/secret "$ROUNDS"
    sed -n 's/.* refused=\([0-9]*\) ns_per_round=\([0-9]*\).*/fileloop-denied-ns-per-round '"$mode $repetition"' \2 refused=\1/p' "/tmp/out.fileloop-denied.${mode}"
    rm -rf /tmp/work/javac/out && mkdir -p /tmp/work/javac/out
    measure javac "$mode" "$repetition" bash -c 'javac -d /tmp/work/javac/out /tmp/work/javac/src/*.java'
    rm -rf /tmp/work/mvn/target
    measure maven "$mode" "$repetition" bash -c 'cd /tmp/work/mvn && mvn -o -B test'
  done
done

echo "--- reporter summaries of the last repetition"
for label in fileloop-allowed fileloop-denied javac maven; do
  printf '%s: ' "$label"
  grep -c 'Phobos Security Error' "/tmp/err.${label}.report" | tr '\n' ' ' || true
  grep 'notifications,' "/tmp/err.${label}.report" || true
  grep 'trapped' "/tmp/err.${label}.report" || true
done
echo "--- distinct messages of the Maven run"
grep 'Phobos Security Error' /tmp/err.maven.report | sort | uniq -c | sort -rn | head -40 || true
echo "--- Maven result in each mode"
for mode in "${MODES[@]}"; do
  printf '%s: ' "$mode"
  grep -E 'Tests run:|BUILD' "/tmp/out.maven.${mode}" | tail -n 2 | tr '\n' ' ' || true
  echo
done
