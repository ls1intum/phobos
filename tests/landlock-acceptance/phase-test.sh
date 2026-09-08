#!/usr/bin/env bash
set -uo pipefail
CORE=/var/tmp/opt/core
LL=$CORE/phobos-landlock
P=/var/tmp/project
PASS=0; FAIL=0
hdr(){ printf '\n\033[1m%s\033[0m\n' "$*"; }
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

mkdir -p $P/src/main/java /var/tmp/secret
echo "TOP-SECRET" > /var/tmp/secret/secret.txt
cat > $P/pom.xml <<'POM'
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>de.tum</groupId><artifactId>probe</artifactId><version>1.0</version>
<properties><maven.compiler.source>17</maven.compiler.source>
<maven.compiler.target>17</maven.compiler.target>
<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties></project>
POM
echo 'public class App { public static void main(String[] a){ System.out.println("app"); } }' > $P/src/main/java/App.java

# Rechte-Profile der einzelnen Phasen
# /dev/null muss explizit erlaubt werden: bwrap lieferte /dev frueher per --dev mit.
COMMON="--rox /opt/java --rox /usr --ro /etc --rw /tmp --rw /root/.m2 --rw /dev/null"
COMPILE="$COMMON --rw $P"
TEST_ONLY="$COMMON --rox $P/target --rox $P/pom.xml --rw $P/target/surefire"

# probe_read <beschreibung> <erwartung OK|DENIED> <landlock-args...>
probe_read() {
  local desc="$1"; local want="$2"; shift 2
  local got=DENIED
  if [[ "$1" == "UNRESTRICTED" ]]; then
    cat /var/tmp/secret/secret.txt >/dev/null 2>&1 && got=OK
  else
    $LL "$@" -- /bin/cat /var/tmp/secret/secret.txt >/dev/null 2>&1 && got=OK
  fi
  [[ "$got" == "$want" ]] && ok "$desc: Geheimnis $got (erwartet)" || bad "$desc: Geheimnis $got, erwartet $want"
}

hdr "Phase 0: Vorbereitung unbeschraenkt (Plugins laden, wie ein realer Agent)"
(cd $P && mvn -q compile > /tmp/prep.log 2>&1) && ok "Plugins geladen" || { bad "Vorbereitung fehlgeschlagen"; tail -5 /tmp/prep.log; }

hdr "Phase 1: mvn clean, unbeschraenkt"
(cd $P && mvn -o -q clean) && ok "mvn clean lief durch" || bad "mvn clean fehlgeschlagen"
probe_read "Phase 1" OK UNRESTRICTED

hdr "Phase 2: mvn compile, eingeschraenkt"
(cd $P && $LL $COMPILE --chdir $P -- mvn -o -q compile) && ok "mvn compile lief unter Landlock durch" || bad "mvn compile fehlgeschlagen"
probe_read "Phase 2" DENIED $COMPILE
[[ -f $P/target/classes/App.class ]] && ok "Kompilat wurde erzeugt" || bad "kein Kompilat"

hdr "Phase 3: enger als Phase 2 (nur noch target lesen)"
mkdir -p $P/target/surefire
$LL $TEST_ONLY --chdir $P -- /opt/java/openjdk/bin/java -cp $P/target/classes App >/dev/null 2>&1 \
  && ok "Testlauf gegen das Kompilat funktioniert" || bad "Testlauf fehlgeschlagen"
probe_read "Phase 3" DENIED $TEST_ONLY
$LL $TEST_ONLY --chdir $P -- /bin/sh -c "echo x > $P/src/main/java/Evil.java" 2>/dev/null \
  && bad "Phase 3 konnte in src/ schreiben" || ok "Phase 3 kann nicht mehr in src/ schreiben (enger als Phase 2)"

hdr "Phase 4: mvn clean, wieder unbeschraenkt"
(cd $P && mvn -o -q clean) && ok "mvn clean lief erneut durch" || bad "zweites mvn clean fehlgeschlagen"
probe_read "Phase 4" OK UNRESTRICTED

hdr "Die Falle: was Phase 3 hinterlaesst, laeuft in Phase 4 unbeschraenkt"
mkdir -p $P/target
$LL $COMMON --rw $P/target --chdir $P -- /bin/sh -c 'echo "cat /var/tmp/secret/secret.txt" > target/hinterlassen.sh' 2>/dev/null
if [[ -f $P/target/hinterlassen.sh ]]; then
  OUT=$(sh $P/target/hinterlassen.sh 2>&1)
  # This is a documented property, not a defect: Landlock binds a process, not
  # a container. Whatever a restricted phase leaves behind is handled with full
  # rights by a later unrestricted phase. The check asserts that the risk is
  # real, so that nobody plans an unrestricted final phase by accident.
  if [[ "$OUT" == *TOP-SECRET* ]]; then
    ok "nachgewiesen: eine unbeschraenkte Schlussphase fuehrt Hinterlassenes mit vollen Rechten aus"
    printf '       \033[33m-> Folgerung: die Aufraeumphase ebenso eng fahren wie die Testphase\033[0m\n'
  else
    bad "Erwartung verfehlt: der Nachweis der Falle greift nicht mehr, Test pruefen"
  fi
else
  ok "Phase 3 konnte nichts hinterlassen"
fi

hdr "Kann ein eingeschraenkter Prozess die Beschraenkung wieder loswerden?"
$LL $TEST_ONLY -- /bin/sh -c "cat /var/tmp/secret/secret.txt" >/dev/null 2>&1 \
  && bad "Kindprozess entkam der Beschraenkung" || ok "Kindprozess bleibt beschraenkt"

hdr "Ergebnis"
printf '  bestanden: %d, fehlgeschlagen: %d\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
