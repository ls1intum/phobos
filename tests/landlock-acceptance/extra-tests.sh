#!/usr/bin/env bash
set -uo pipefail
CORE=/var/tmp/opt/core
# The image carries the constants beside the scripts under test.
# shellcheck source=/dev/null
source "${CORE}/phobos-constants.sh"
# How many lines of a failing command's output a failure shows, the uid of the unprivileged
# user the non-root checks run as, the loopback ports of the network checks (the policy allows
# the first and not the second), and how often and how far apart the server's start is awaited.
LOG_EXCERPT_LINES=4
SANDBOX_UID=1042
ALLOWED_PORT=19001
DENIED_PORT=19002
SERVER_WAIT_ATTEMPTS=40
SERVER_WAIT_SECONDS=0.2
TD=/var/tmp/testing-dir
PASS=0
FAIL=0
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
  local want="$1"; shift
  local desc="$1"; shift
  local out; out=$(phobos.sh -- java -cp probe PhobosProbe "$@" 2>&1)
  local got; got=$(printf '%s\n' "$out" | grep '^RESULT ' | head -1 | awk '{print $2}')
  if [[ "$got" == "$want" ]]; then ok "$desc -> $got"
  else bad "$desc -> expected $want, got ${got:-<nothing>}"; printf '%s\n' "$out" | sed 's/^/       | /' | tail -n "$LOG_EXCERPT_LINES"; fi
}

hdr "A. Does a freshly started child process inherit the sandbox?"
probe DENIED "ProcessBuilder: cat /var/tmp/secret/secret.txt" spawn /bin/cat /var/tmp/secret/secret.txt
probe OK     "ProcessBuilder: cat allowed file"               spawn /bin/cat "$TD/allowed-ro/data.txt"

hdr "B. Can a second JVM break out from inside the sandbox?"
B_OUT=$(phobos.sh -- java -cp probe PhobosProbe spawn /opt/java/openjdk/bin/java -cp "$TD/probe" PhobosProbe read /var/tmp/secret/secret.txt 2>&1)
if printf '%s' "$B_OUT" | grep -q 'RESULT DENIED read /var/tmp/secret/secret.txt'; then
  ok "Second JVM from inside the sandbox: the forbidden file stays blocked"
else
  bad "The second JVM could break out"; printf '%s\n' "$B_OUT" | sed 's/^/       | /' | tail -n "$LOG_EXCERPT_LINES"
fi

hdr "C. Cross-check: would bubblewrap stand any chance at all in this container?"
if unshare -Ur true 2>/dev/null; then
  bad "unshare -Ur succeeds: the container has more rights than an Artemis build container"
else
  ok "unshare -Ur fails ($(unshare -Ur true 2>&1 | head -1)) -> bwrap could not run here"
fi
if [[ -x /usr/bin/bwrap ]]; then bad "bwrap is still in the image"; else ok "bwrap is no longer in the image"; fi

hdr "D. The same picture as non-root (Artemis does not run the build script as root)"
useradd -m -u "$SANDBOX_UID" sandboxuser 2>/dev/null || true
SU=sandboxuser
id "$SU" >/dev/null 2>&1 || SU=nobody
su -s /bin/bash "$SU" -c "export PATH=/opt/java/openjdk/bin:\$PATH; cd $TD && $CORE/phobos.sh -- java -cp probe PhobosProbe read /var/tmp/secret/secret.txt" > /tmp/nonroot.log 2>&1
if grep -q 'RESULT DENIED read ' /tmp/nonroot.log; then ok "As $SU: the forbidden file stays blocked"
else bad "As $SU: unexpected result"; sed 's/^/       | /' /tmp/nonroot.log | tail -n \"$LOG_EXCERPT_LINES\"; fi
su -s /bin/bash "$SU" -c "export PATH=/opt/java/openjdk/bin:\$PATH; cd $TD && $CORE/phobos.sh -- java -cp probe PhobosProbe read $TD/allowed-ro/data.txt" > /tmp/nonroot2.log 2>&1
if grep -q 'RESULT OK read ' /tmp/nonroot2.log; then ok "As $SU: the allowed file is still readable"
else bad "As $SU: the allowed file is not readable"; sed 's/^/       | /' /tmp/nonroot2.log | tail -n \"$LOG_EXCERPT_LINES\"; fi

hdr "F. Redirectable write paths are rejected"
# A write path that is a symlink must not redirect the rule.
ln -sfn /var/tmp/secret $TD/redirect 2>/dev/null
# Collect the output first: under "set -o pipefail" the wrapper's exit code (125,
# intended) would make the pipeline fail even though grep finds a match.
SYM_OUT=$($CORE/phobos-landlock --rights=rx /usr --rights=rwmd $TD/redirect -- /bin/true 2>&1)
if printf '%s' "$SYM_OUT" | grep -q "symbolic link"; then
  ok "A symbolic write path is rejected (no redirection of the rule)"
else
  bad "A symbolic write path was accepted"
fi

# A Landlock version no kernel offers.
ABOVE_EVERY_LANDLOCK_VERSION=99
hdr "G. Wrapper options that no policy file reaches"
LL=$CORE/phobos-landlock
$LL --minimum-landlock-version "$ABOVE_EVERY_LANDLOCK_VERSION" --rights=rx /usr -- /bin/true >/dev/null 2>&1
[[ $? -eq "$PHB_ENFORCER_REFUSED_EXIT" ]] && ok "--minimum-landlock-version above the kernel version aborts instead of running unprotected" \
                 || bad "--minimum-landlock-version 99 ran to completion"
$LL --minimum-landlock-version 1 --rights=rx /usr -- /bin/true >/dev/null 2>&1
[[ $? -eq 0 ]] && ok "--minimum-landlock-version below the kernel version runs" || bad "--minimum-landlock-version 1 failed"
$LL --unknown-option x --rights=rx /usr -- /bin/true >/dev/null 2>&1
[[ $? -eq "$PHB_EXIT_USAGE" ]] && ok "An unknown option is rejected" || bad "An unknown option was accepted"
# Network rules: the allowed port gets through, any other does not.
NETDIR=$(mktemp -d); cat > "$NETDIR/N.java" <<'JAVA'
import java.net.*;
public class N {
  /** How long the servers stay up, far past the checks, and how long a connect may take. */
  private static final long HOLD_MILLISECONDS = 60000L;
  private static final int CONNECT_TIMEOUT_MILLISECONDS = 2000;
  public static void main(String[] a) throws Exception {
    if (a[0].equals("serve")) {
      ServerSocket s1 = new ServerSocket(Integer.parseInt(a[1]));
      ServerSocket s2 = new ServerSocket(Integer.parseInt(a[2]));
      new Thread(() -> { try { while (true) { s1.accept(); } } catch (Exception e) { } }).start();
      new Thread(() -> { try { while (true) { s2.accept(); } } catch (Exception e) { } }).start();
      System.out.println("ready");
      Thread.sleep(HOLD_MILLISECONDS);
    } else {
      try (Socket s = new Socket()) {
        s.connect(new InetSocketAddress("127.0.0.1", Integer.parseInt(a[0])), CONNECT_TIMEOUT_MILLISECONDS);
        System.out.println("CONNECTED");
      } catch (Exception e) {
        System.out.println("DENIED");
      }
    }
  }
}
JAVA
javac -d "$NETDIR" "$NETDIR/N.java" 2>/dev/null
java -cp "$NETDIR" N serve "$ALLOWED_PORT" "$DENIED_PORT" > "$NETDIR/srv.log" 2>&1 &
NETSRV=$!
for _ in $(seq 1 "$SERVER_WAIT_ATTEMPTS"); do grep -q ready "$NETDIR/srv.log" 2>/dev/null && break; sleep "$SERVER_WAIT_SECONDS"; done
NB="--rights=rx /opt/java --rights=rx /usr --rights=r /etc --rights=rwmd /tmp --rights=rwmd /dev/null --rights=rx $NETDIR"
if $LL $NB --connect-tcp "$ALLOWED_PORT" -- java -cp "$NETDIR" N "$ALLOWED_PORT" 2>/dev/null | grep -q CONNECTED; then
  ok "--connect-tcp: the allowed port is reachable"
else bad "--connect-tcp: the allowed port was blocked"; fi
if $LL $NB --connect-tcp "$ALLOWED_PORT" -- java -cp "$NETDIR" N "$DENIED_PORT" 2>/dev/null | grep -q DENIED; then
  ok "--connect-tcp: a port that is not allowed stays blocked"
else bad "--connect-tcp: a port that is not allowed was reachable"; fi
kill $NETSRV 2>/dev/null; rm -rf "$NETDIR"

hdr "I. The network policy lies outside the reach of the sandbox"
# /tmp is a write path in this policy. The specification therefore lies under
# /var/tmp, and the rule file in it may be read but not modified.
# No redirection to /dev/null: this policy does not allow /dev/null.
NET_OUT=$(phobos.sh -- /bin/sh -c 'echo "* 0" >> "$NETBLOCKER_CONF" && echo WRITE-OK || echo WRITE-DENIED; cat "$NETBLOCKER_CONF" && echo READ-OK' 2>&1)
if printf '%s' "$NET_OUT" | grep -q WRITE-DENIED && printf '%s' "$NET_OUT" | grep -q READ-OK; then
  ok "The rule file is readable from the sandbox but not writable"
else
  bad "The rule file is writable or not readable from the sandbox"; printf '%s\n' "$NET_OUT" | sed 's/^/       | /' | tail -n "$LOG_EXCERPT_LINES"
fi
# If the specification itself lies beneath a write path, Phobos refuses the run.
SPEC_OUT=$(phobos.sh --spec-parent /tmp -- /bin/true 2>&1)
SPEC_RC=$?
if [[ $SPEC_RC -eq "$PHB_EPOLICY" && "$SPEC_OUT" == *"lies beneath the write path"* ]]; then
  ok "A specification beneath a write path aborts (PHB-EPOLICY)"
else
  bad "Specification beneath a write path: rc=$SPEC_RC"; printf '%s\n' "$SPEC_OUT" | sed 's/^/       | /' | tail -n "$LOG_EXCERPT_LINES"
fi
if ls -d /tmp/phobos-spec.* /var/tmp/phobos-spec.* >/dev/null 2>&1; then
  bad "Specifications are still lying around after the runs: $(ls -d /tmp/phobos-spec.* /var/tmp/phobos-spec.* 2>/dev/null | tr '\n' ' ')"
else
  ok "No specification remains after the runs"
fi

hdr "E. Control probe: without the sandbox the file is readable for the same user"
if su -s /bin/bash "$SU" -c "cat /var/tmp/secret/secret.txt" >/dev/null 2>&1; then
  ok "Readable without the sandbox -> the block above came from Landlock, not from file permissions"
else
  bad "Not readable even without the sandbox -> the test measures file permissions instead of Landlock"
fi

# --------------------------------------------------------------------------
# F. What the finer-grained set of rights changes
# --------------------------------------------------------------------------
LL="$CORE/phobos-landlock"
BASE="--rights=rx /usr --rights=rx /lib --rights=rx /bin --rights=r /etc"
mkdir -p "$TD/fine"; chmod 777 "$TD/fine"

denied() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then bad "$desc -> allowed, expected denied"
  else ok "$desc -> denied"; fi
}
allowed() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc -> allowed"
  else bad "$desc -> denied, expected allowed"; fi
}

hdr "F. Rights can be controlled individually"
allowed "w allows writing to an existing file" \
  sh -c "echo old > $TD/fine/f.txt; $LL $BASE --rights=rw $TD/fine -- /bin/sh -c 'echo new > $TD/fine/f.txt'"
denied  "w alone does not allow creating" \
  $LL $BASE --rights=rw "$TD/fine" -- /bin/sh -c "echo x > $TD/fine/new1.txt"
allowed "m allows creating" \
  $LL $BASE --rights=rwm "$TD/fine" -- /bin/sh -c "echo x > $TD/fine/new2.txt"
denied  "m alone does not allow deleting" \
  $LL $BASE --rights=rwm "$TD/fine" -- /bin/rm -f "$TD/fine/new2.txt"
allowed "d allows deleting" \
  $LL $BASE --rights=rwmd "$TD/fine" -- /bin/rm -f "$TD/fine/new2.txt"

# The device numbers of /dev/null, for a device node the sandbox must not be able to make.
NULL_DEVICE_MAJOR=1
NULL_DEVICE_MINOR=3
hdr "G. What is no longer granted at all"
denied "create a device file" \
  $LL $BASE --rights=rwmd "$TD/fine" -- /bin/sh -c "mknod $TD/fine/device c ${NULL_DEVICE_MAJOR} ${NULL_DEVICE_MINOR}"
denied "create a symbolic link" \
  $LL $BASE --rights=rwmd "$TD/fine" -- /bin/ln -s /etc/passwd "$TD/fine/link"
allowed "creating an ordinary file still works" \
  $LL $BASE --rights=rwmd "$TD/fine" -- /bin/sh -c "echo x > $TD/fine/ordinary.txt"

hdr "H. Inherited rights are reported, not concealed"
# Landlock adds up the rights of all rules along a path. A subdirectory therefore
# inherits what its ancestor grants, and the policy then states less than actually
# applies. This is reported and the effective set of rights is passed on, so that
# the output does not lie.
#
# The hard case, a genuine narrowing beneath a wider ancestor, can now be expressed
# with the per-right sections (for instance [read] on a subpath beneath [read] and
# [write] on the ancestor) and is covered by the unit tests. What remains here is the
# reported, not rejected, case.
INHERITED_SPEC=$(mktemp -d); for f in read.paths execute.paths write.paths create.paths delete.paths tail.flags net.rules; do : > "$INHERITED_SPEC/$f"; done
printf '%s\n' "$TD/fine" > "$INHERITED_SPEC/read.paths"
printf '%s\n' "$TD" > "$INHERITED_SPEC/write.paths"
OUT=$("$CORE/phobos-filesystem.sh" "$INHERITED_SPEC" -- /bin/true 2>&1)
if printf '%s' "$OUT" | grep -q "effectively holds"; then
  ok "An inherited widening is named instead of being silently adopted"
else
  bad "An inherited widening was not reported"; printf '%s\n' "$OUT" | sed 's/^/       | /' | tail -n "$LOG_EXCERPT_LINES"
fi
rm -rf "$INHERITED_SPEC"


hdr "Result of the additional tests"
printf '  passed: %d, failed: %d\n\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
