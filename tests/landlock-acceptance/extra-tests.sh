#!/usr/bin/env bash
set -uo pipefail
CORE=/var/tmp/opt/core
TD=/var/tmp/testing-dir
PASS=0; FAIL=0
hdr() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()  { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

mkdir -p "$TD/probe" "$TD/allowed-ro" "$TD/allowed-rw" /var/tmp/secret
echo "public-data" > "$TD/allowed-ro/data.txt"
echo "TOP-SECRET-TESTCASE" > /var/tmp/secret/secret.txt
javac -d "$TD/probe" /testsuite/PhobosProbe.java || exit 1
cp /testsuite/BaseLanguage-java.cfg "$CORE/BaseLanguage-java.cfg"
chmod -R a+rX "$TD" /var/tmp/opt /var/tmp/secret; chmod a+w "$TD/allowed-rw"
chmod 755 /var/tmp/secret; chmod 644 /var/tmp/secret/secret.txt

probe() {
  local want="$1"; shift; local desc="$1"; shift
  local out; out=$(phobos.sh -- java -cp probe PhobosProbe "$@" 2>&1)
  local got; got=$(printf '%s\n' "$out" | grep '^RESULT ' | head -1 | awk '{print $2}')
  if [[ "$got" == "$want" ]]; then ok "$desc -> $got"
  else bad "$desc -> erwartet $want, bekommen ${got:-<nichts>}"; printf '%s\n' "$out" | sed 's/^/       | /' | tail -4; fi
}

hdr "A. Vererbt ein frisch gestarteter Kindprozess die Sandbox?"
probe DENIED "ProcessBuilder: cat /var/tmp/secret/secret.txt" spawn /bin/cat /var/tmp/secret/secret.txt
probe OK     "ProcessBuilder: cat erlaubte Datei"             spawn /bin/cat "$TD/allowed-ro/data.txt"

hdr "B. Kann eine zweite JVM aus der Sandbox heraus ausbrechen?"
B_OUT=$(phobos.sh -- java -cp probe PhobosProbe spawn /opt/java/openjdk/bin/java -cp "$TD/probe" PhobosProbe read /var/tmp/secret/secret.txt 2>&1)
if printf '%s' "$B_OUT" | grep -q 'RESULT DENIED read /var/tmp/secret/secret.txt'; then
  ok "zweite JVM aus der Sandbox heraus: verbotene Datei bleibt gesperrt"
else
  bad "zweite JVM konnte ausbrechen"; printf '%s\n' "$B_OUT" | sed 's/^/       | /' | tail -4
fi

hdr "C. Gegenprobe: haette bubblewrap in diesem Container ueberhaupt eine Chance?"
if unshare -Ur true 2>/dev/null; then
  bad "unshare -Ur gelingt: Container hat mehr Rechte als ein Artemis-Build-Container"
else
  ok "unshare -Ur scheitert ($(unshare -Ur true 2>&1 | head -1)) -> bwrap koennte hier nicht laufen"
fi
if [[ -x /usr/bin/bwrap ]]; then bad "bwrap ist noch im Image"; else ok "bwrap ist nicht mehr im Image"; fi

hdr "D. Gleiches Bild als Nicht-Root (Artemis fuehrt das Build-Skript nicht als root aus)"
useradd -m -u 1042 sandboxuser 2>/dev/null || true
SU=sandboxuser
id "$SU" >/dev/null 2>&1 || SU=nobody
su -s /bin/bash "$SU" -c "export PATH=/opt/java/openjdk/bin:\$PATH; cd $TD && $CORE/phobos.sh -- java -cp probe PhobosProbe read /var/tmp/secret/secret.txt" > /tmp/nonroot.log 2>&1
if grep -q 'RESULT DENIED read ' /tmp/nonroot.log; then ok "als $SU: verbotene Datei bleibt gesperrt"
else bad "als $SU unerwartet"; sed 's/^/       | /' /tmp/nonroot.log | tail -4; fi
su -s /bin/bash "$SU" -c "export PATH=/opt/java/openjdk/bin:\$PATH; cd $TD && $CORE/phobos.sh -- java -cp probe PhobosProbe read $TD/allowed-ro/data.txt" > /tmp/nonroot2.log 2>&1
if grep -q 'RESULT OK read ' /tmp/nonroot2.log; then ok "als $SU: erlaubte Datei weiterhin lesbar"
else bad "als $SU: erlaubte Datei nicht lesbar"; sed 's/^/       | /' /tmp/nonroot2.log | tail -4; fi

hdr "F. Nicht durchsetzbare Policy und umlenkbare Schreibpfade werden abgelehnt"
# hide-Pfad unterhalb eines erlaubten Baums: Landlock kann das nicht aussparen
SPEC=$(mktemp -d); for f in ro.paths rw.paths hide.paths tail.flags net.rules; do : > "$SPEC/$f"; done
echo "$TD"            > "$SPEC/ro.paths"
echo "$TD/allowed-ro" > "$SPEC/hide.paths"
OUT=$(PHB_ENABLE_FILESYSTEM=1 bash $CORE/phobos-filesystem.sh "$SPEC" -- /bin/true 2>&1); RC=$?
if [[ $RC -eq 11 && "$OUT" == *"unenforceable"* ]]; then
  ok "hide unterhalb eines erlaubten Baums bricht ab (PHB-EPOLICY) statt Sicherheit vorzutaeuschen"
else
  bad "unerwartet: rc=$RC out=$OUT"
fi
# Schreibpfad, der ein Symlink ist: darf die Regel nicht umlenken
ln -sfn /var/tmp/secret $TD/umleitung 2>/dev/null
# Ausgabe erst einsammeln: unter "set -o pipefail" wuerde der Exit-Code des
# Wrappers (125, gewollt) die Pipeline scheitern lassen, obwohl grep faendig wird.
SYM_OUT=$($CORE/phobos-landlock --rights=rx /usr --rights=rwmd $TD/umleitung -- /bin/true 2>&1)
if printf '%s' "$SYM_OUT" | grep -q "symbolic link"; then
  ok "symbolischer Schreibpfad wird abgelehnt (keine Umlenkung der Regel)"
else
  bad "symbolischer Schreibpfad wurde akzeptiert"
fi

hdr "G. Optionen des Wrappers, die keine Policy-Datei erreicht"
LL=$CORE/phobos-landlock
$LL --minimum-landlock-version 99 --rights=rx /usr -- /bin/true >/dev/null 2>&1
[[ $? -eq 125 ]] && ok "--minimum-landlock-version ueber der Kernel-Version bricht ab statt ungeschuetzt zu laufen" \
                 || bad "--minimum-landlock-version 99 lief durch"
$LL --minimum-landlock-version 1 --rights=rx /usr -- /bin/true >/dev/null 2>&1
[[ $? -eq 0 ]] && ok "--minimum-landlock-version unterhalb der Kernel-Version laeuft" || bad "--minimum-landlock-version 1 schlug fehl"
$LL --unbekannte-option x --rights=rx /usr -- /bin/true >/dev/null 2>&1
[[ $? -eq 2 ]] && ok "unbekannte Option wird abgewiesen" || bad "unbekannte Option akzeptiert"
# Netzregeln: der erlaubte Port kommt durch, ein anderer nicht
NETDIR=$(mktemp -d); cat > "$NETDIR/N.java" <<'JAVA'
import java.net.*;
public class N {
  public static void main(String[] a) throws Exception {
    if (a[0].equals("serve")) {
      ServerSocket s1 = new ServerSocket(19001);
      ServerSocket s2 = new ServerSocket(19002);
      new Thread(() -> { try { while (true) { s1.accept(); } } catch (Exception e) { } }).start();
      new Thread(() -> { try { while (true) { s2.accept(); } } catch (Exception e) { } }).start();
      System.out.println("ready");
      Thread.sleep(60000L);
    } else {
      try (Socket s = new Socket()) {
        s.connect(new InetSocketAddress("127.0.0.1", Integer.parseInt(a[0])), 2000);
        System.out.println("CONNECTED");
      } catch (Exception e) {
        System.out.println("DENIED");
      }
    }
  }
}
JAVA
javac -d "$NETDIR" "$NETDIR/N.java" 2>/dev/null
java -cp "$NETDIR" N serve > "$NETDIR/srv.log" 2>&1 &
NETSRV=$!
for _ in $(seq 1 40); do grep -q ready "$NETDIR/srv.log" 2>/dev/null && break; sleep 0.2; done
NB="--rights=rx /opt/java --rights=rx /usr --rights=r /etc --rights=rwmd /tmp --rights=rwmd /dev/null --rights=rx $NETDIR"
if $LL $NB --connect-tcp 19001 -- java -cp "$NETDIR" N 19001 2>/dev/null | grep -q CONNECTED; then
  ok "--connect-tcp: der erlaubte Port ist erreichbar"
else bad "--connect-tcp: erlaubter Port wurde blockiert"; fi
if $LL $NB --connect-tcp 19001 -- java -cp "$NETDIR" N 19002 2>/dev/null | grep -q DENIED; then
  ok "--connect-tcp: ein nicht erlaubter Port bleibt gesperrt"
else bad "--connect-tcp: nicht erlaubter Port war erreichbar"; fi
kill $NETSRV 2>/dev/null; rm -rf "$NETDIR"

hdr "E. Kontrollprobe: ohne Sandbox ist die Datei fuer denselben Benutzer lesbar"
if su -s /bin/bash "$SU" -c "cat /var/tmp/secret/secret.txt" >/dev/null 2>&1; then
  ok "ohne Sandbox lesbar -> die Sperre oben kam von Landlock, nicht von Dateirechten"
else
  bad "auch ohne Sandbox nicht lesbar -> Test misst Dateirechte statt Landlock"
fi

# --------------------------------------------------------------------------
# F. Was der feinere Rechtesatz aendert
# --------------------------------------------------------------------------
LL="$CORE/phobos-landlock"
BASE="--rights=rx /usr --rights=rx /lib --rights=rx /bin --rights=r /etc"
mkdir -p "$TD/fein"; chmod 777 "$TD/fein"

denied() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then bad "$desc -> erlaubt, erwartet verweigert"
  else ok "$desc -> verweigert"; fi
}
allowed() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc -> erlaubt"
  else bad "$desc -> verweigert, erwartet erlaubt"; fi
}

hdr "F. Rechte lassen sich einzeln steuern"
allowed "w erlaubt das Beschreiben einer vorhandenen Datei" \
  sh -c "echo alt > $TD/fein/f.txt; $LL $BASE --rights=rw $TD/fein -- /bin/sh -c 'echo neu > $TD/fein/f.txt'"
denied  "w allein erlaubt kein Anlegen" \
  $LL $BASE --rights=rw "$TD/fein" -- /bin/sh -c "echo x > $TD/fein/neu1.txt"
allowed "m erlaubt das Anlegen" \
  $LL $BASE --rights=rwm "$TD/fein" -- /bin/sh -c "echo x > $TD/fein/neu2.txt"
denied  "m allein erlaubt kein Loeschen" \
  $LL $BASE --rights=rwm "$TD/fein" -- /bin/rm -f "$TD/fein/neu2.txt"
allowed "d erlaubt das Loeschen" \
  $LL $BASE --rights=rwmd "$TD/fein" -- /bin/rm -f "$TD/fein/neu2.txt"

hdr "G. Was ueberhaupt nicht mehr erteilt wird"
denied "eine Geraetedatei anlegen" \
  $LL $BASE --rights=rwmd "$TD/fein" -- /bin/sh -c "mknod $TD/fein/geraet c 1 3"
denied "einen symbolischen Link anlegen" \
  $LL $BASE --rights=rwmd "$TD/fein" -- /bin/ln -s /etc/passwd "$TD/fein/link"
allowed "eine gewoehnliche Datei anlegen geht weiter" \
  $LL $BASE --rights=rwmd "$TD/fein" -- /bin/sh -c "echo x > $TD/fein/gewoehnlich.txt"

hdr "H. Geerbte Rechte werden gemeldet, nicht verschwiegen"
# Landlock addiert die Rechte aller Regeln entlang eines Pfades. Ein
# Unterverzeichnis erbt also, was sein Vorfahr erteilt, und die Politik sagt
# dann weniger, als tatsaechlich gilt. Das wird gemeldet und die geltende
# Rechtemenge wird uebergeben, damit die Ausgabe nicht luegt.
#
# Der harte Fall, eine echte Verengung unterhalb eines weiteren Vorfahren, ist
# ueber die Politikdateien noch nicht erreichbar: [readonly] erteilt rx und
# [write] erteilt rwmd, und keine der beiden Mengen liegt ganz in der anderen.
# Er wird von den Einheitstests abgedeckt und wird hier pruefbar, sobald das
# Format einen dritten Abschnitt fuer reine Daten kennt.
WEITER=$(mktemp -d); for f in ro.paths rw.paths hide.paths tail.flags net.rules; do : > "$WEITER/$f"; done
printf '%s\n' "$TD/fein" > "$WEITER/ro.paths"
printf '%s\n' "$TD" > "$WEITER/rw.paths"
OUT=$(PHB_ENABLE_FILESYSTEM=1 "$CORE/phobos-filesystem.sh" "$WEITER" -- /bin/true 2>&1)
if printf '%s' "$OUT" | grep -q "effectively holds"; then
  ok "geerbte Erweiterung wird benannt statt stillschweigend uebernommen"
else
  bad "geerbte Erweiterung wurde nicht gemeldet"; printf '%s\n' "$OUT" | sed 's/^/       | /' | tail -3
fi
rm -rf "$WEITER"


hdr "Ergebnis Zusatztests"
printf '  bestanden: %d, fehlgeschlagen: %d\n\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
