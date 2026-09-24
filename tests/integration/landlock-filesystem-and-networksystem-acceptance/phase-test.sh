#!/usr/bin/env bash
# The rights of a run, tightened and widened across four phases in one container.
#
# A grading run is not one command: it compiles, then tests, then cleans up, and each
# phase deserves its own rights. This walks a Maven project through four of them and
# checks, at each, that what the phase needs works and what it does not need is denied.
#
# The last part is the trap: what a restricted phase leaves behind is run by a later
# unrestricted phase with that phase's rights. It is a documented property of Landlock,
# which binds a process rather than a container, and the check asserts that the risk is
# real so that nobody plans an unrestricted final phase by accident.
#
# Every step is offline, so it needs no network. It needs the run-phase image and an
# ordinary container: no --privileged, no --cap-add, no --security-opt. PHOBOS_HOME names
# where Phobos is installed in that image.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE=/var/tmp/opt/core
# How many lines of a failing build's log a failure shows.
LOG_EXCERPT_LINES=5
LL=$CORE/phobos-landlock-filesystem-and-networksystem
P=/var/tmp/project
hdr(){ printf '\n\033[1m%s\033[0m\n' "$*"; }

mkdir -p $P/src/main/java /var/tmp/secret
echo "TOP-SECRET" > /var/tmp/secret/secret.txt
cat > $P/pom.xml <<'POM'
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>de.tum</groupId><artifactId>probe</artifactId><version>1.0</version>
<properties><maven.compiler.source>17</maven.compiler.source>
<maven.compiler.target>17</maven.compiler.target>
<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>
<build><pluginManagement><plugins>
<plugin><groupId>org.apache.maven.plugins</groupId>
<artifactId>maven-compiler-plugin</artifactId><version>3.14.0</version></plugin>
</plugins></pluginManagement></build></project>
POM
echo 'public class App { public static void main(String[] a){ System.out.println("app"); } }' > $P/src/main/java/App.java

# The rights profiles of the individual phases.
# /dev/null must be allowed explicitly: Landlock grants nothing that is not named, /dev
# included.
COMMON="--rights=rx /opt/java --rights=rx /usr --rights=r /etc --rights=rwmd /tmp --rights=rwmd /root/.m2 --rights=rwmd /dev/null"
COMPILE="$COMMON --rights=rwmd $P"
TEST_ONLY="$COMMON --rights=rx $P/target --rights=rx $P/pom.xml --rights=rwmd $P/target/surefire"

# probe_read <description> <expectation OK|DENIED> <landlock-args...>
probe_read() {
  local desc="$1"
  local want="$2"
  shift 2
  local got=DENIED
  if [[ "$1" == "UNRESTRICTED" ]]; then
    cat /var/tmp/secret/secret.txt >/dev/null 2>&1 && got=OK
  else
    $LL "$@" -- /bin/cat /var/tmp/secret/secret.txt >/dev/null 2>&1 && got=OK
  fi
  [[ "$got" == "$want" ]] && ok "$desc: secret $got (expected)" || bad "$desc: secret $got, expected $want"
}

# Offline like every other step. The base image brings its own Maven repository,
# so nothing needs to be downloaded here; the compiler plugin version is set in
# the POM above because Maven's default would be 3.13.0 and the image holds only
# 3.14.0. A network access at this point could make the run fail without it
# having anything to do with Landlock.
hdr "Phase 0: preparation, unrestricted (baseline, without restriction)"
(cd $P && mvn -o -q compile > /tmp/prep.log 2>&1) && ok "Baseline compiled" || { bad "Preparation failed"; tail -n "$LOG_EXCERPT_LINES" /tmp/prep.log; }

hdr "Phase 1: mvn clean, unrestricted"
(cd $P && mvn -o -q clean) && ok "mvn clean completed" || bad "mvn clean failed"
probe_read "Phase 1" OK UNRESTRICTED

hdr "Phase 2: mvn compile, restricted"
(cd $P && $LL $COMPILE --chdir $P -- mvn -o -q compile) && ok "mvn compile completed under Landlock" || bad "mvn compile failed"
probe_read "Phase 2" DENIED $COMPILE
[[ -f $P/target/classes/App.class ]] && ok "Compiled output was produced" || bad "No compiled output"

hdr "Phase 3: narrower than phase 2 (only reading target now)"
mkdir -p $P/target/surefire
$LL $TEST_ONLY --chdir $P -- /opt/java/openjdk/bin/java -cp $P/target/classes App >/dev/null 2>&1 \
  && ok "Test run against the compiled output works" || bad "Test run failed"
probe_read "Phase 3" DENIED $TEST_ONLY
$LL $TEST_ONLY --chdir $P -- /bin/sh -c "echo x > $P/src/main/java/Evil.java" 2>/dev/null \
  && bad "Phase 3 could write to src/" || ok "Phase 3 can no longer write to src/ (narrower than phase 2)"

hdr "Phase 4: mvn clean, unrestricted again"
(cd $P && mvn -o -q clean) && ok "mvn clean completed again" || bad "Second mvn clean failed"
probe_read "Phase 4" OK UNRESTRICTED

hdr "The trap: what phase 3 leaves behind runs unrestricted in phase 4"
mkdir -p $P/target
$LL $COMMON --rights=rwmd $P/target --chdir $P -- /bin/sh -c 'echo "cat /var/tmp/secret/secret.txt" > target/left-behind.sh' 2>/dev/null
if [[ -f $P/target/left-behind.sh ]]; then
  OUT=$(sh $P/target/left-behind.sh 2>&1)
  # This is a documented property, not a defect: Landlock binds a process, not
  # a container. Whatever a restricted phase leaves behind is handled with full
  # rights by a later unrestricted phase. The check asserts that the risk is
  # real, so that nobody plans an unrestricted final phase by accident.
  if [[ "$OUT" == *TOP-SECRET* ]]; then
    ok "Demonstrated: an unrestricted final phase runs what was left behind with full rights"
    printf '       \033[33m-> Consequence: run the clean-up phase as narrowly as the test phase\033[0m\n'
  else
    bad "Expectation not met: the demonstration of the trap no longer works, check the test"
  fi
else
  bad "Phase 3 could not leave anything behind, so the trap was never demonstrated"
fi

hdr "Can a restricted process shed its restriction again?"
$LL $TEST_ONLY -- /bin/sh -c "cat /var/tmp/secret/secret.txt" >/dev/null 2>&1 \
  && bad "The child process escaped the restriction" || ok "The child process stays restricted"

hdr "Result"

finish
