#!/usr/bin/env bash
# Runs the SHIPPED Java policy end to end, in both directions.
#
# Every other acceptance script swaps in its own tight test policy, so no suite ever ran
# protecter/src/config/BaseLanguage-java-gradle.cfg, the policy an exercise actually gets. This one applies
# it through phobos.sh, as baked into the run-phase image, and checks that a normal exercise
# still works under it (read its files, write its build output, use /dev/null and
# /dev/urandom) and that a path outside the allow-list stays denied.
#
# The probe uses absolute paths on purpose, so it does not depend on the working directory's
# contents. The shipped policy now grants read on /var/tmp/testing-dir itself, so the JVM's
# user.dir resolves and relative paths would work too; absolute paths keep this suite
# independent of that grant either way.
#
# It needs the run-phase image and an ordinary container: no --privileged, no --cap-add,
# no --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
EXERCISE=/var/tmp/testing-dir
check_base_set "$CORE" BaseLanguage-java-gradle.cfg

# A minimal exercise under the directory the shipped policy names.
mkdir -p "$EXERCISE/assignment" "$EXERCISE/build"
printf 'inside-data\n' > "$EXERCISE/assignment/data.txt"
# A secret outside every allowed tree: /var/tmp is not granted, only /var/tmp/testing-dir's
# children are.
printf 'SECRET\n' > /var/tmp/outside-secret.txt

cat > "$EXERCISE/assignment/Probe.java" <<'JAVA'
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class Probe {
    public static void main(String[] args) throws Exception {
        System.out.println("read-assignment=" + Files.readString(
                Path.of("/var/tmp/testing-dir/assignment/data.txt")).trim());
        Files.writeString(Path.of("/var/tmp/testing-dir/build/out.txt"), "x");
        System.out.println("wrote-build=ok");
        try (FileOutputStream out = new FileOutputStream("/dev/null")) {
            out.write(1);
        }
        System.out.println("dev-null=ok");
        try (FileInputStream in = new FileInputStream("/dev/urandom")) {
            in.read(new byte[8]);
        }
        System.out.println("dev-urandom=ok");
        try {
            Files.readString(Path.of("/var/tmp/outside-secret.txt"));
            System.out.println("outside=READ");
        } catch (Exception denied) {
            System.out.println("outside=denied");
        }
    }
}
JAVA
( cd "$EXERCISE/assignment" && /opt/java/openjdk/bin/javac Probe.java )

# The shipped policy is the Base*.cfg beside phobos.sh; no --config, so this is exactly what
# an exercise runs under.
output="$("$CORE/phobos.sh" -- /opt/java/openjdk/bin/java -cp "$EXERCISE/assignment" Probe 2>&1)"
printf '%s\n' "$output"
echo

# Permitted direction: a normal exercise works under the shipped policy.
for want in "read-assignment=inside-data" "wrote-build=ok" "dev-null=ok" "dev-urandom=ok"; do
  if grep -qF "$want" <<<"$output"; then
    ok "shipped policy permits ${want%%=*}"
  else
    bad "shipped policy permits ${want%%=*}" "$output"
  fi
done

# Containment direction: a path outside the allow-list stays denied.
if grep -qF "outside=denied" <<<"$output"; then
  ok "shipped policy denies a path outside the allow-list"
else
  bad "shipped policy denies a path outside the allow-list" "$output"
fi

# The shipped policy grants Gradle and its workers a server on a port the kernel chooses, and no
# port of their own: a server that takes whatever port it gets runs, one that names a port is
# refused. A run given no --config drops every bind rule, so there is no server at all.
cat > "$EXERCISE/assignment/ServerProbe.java" <<'JAVA'
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerProbe {
    public static void main(String[] args) throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (ServerSocket server = new ServerSocket(0, 50, loopback)) {
            Thread acceptor = new Thread(() -> {
                try (Socket peer = server.accept()) {
                    peer.getOutputStream().write(7);
                } catch (Exception ignored) {
                }
            });
            acceptor.start();
            try (Socket client = new Socket(loopback, server.getLocalPort())) {
                System.out.println("ephemeral-server=ok read=" + client.getInputStream().read());
            }
        } catch (Exception refused) {
            System.out.println("ephemeral-server=denied");
        }
        try (ServerSocket fixed = new ServerSocket(18555, 50, loopback)) {
            System.out.println("fixed-server=OPEN");
        } catch (Exception denied) {
            System.out.println("fixed-server=denied");
        }
        try (DatagramSocket datagram = new DatagramSocket(0, loopback)) {
            System.out.println("ephemeral-udp=ok");
        } catch (Exception refused) {
            System.out.println("ephemeral-udp=denied");
        }
    }
}
JAVA
( cd "$EXERCISE/assignment" && /opt/java/openjdk/bin/javac ServerProbe.java )
printf '[limits]\ntimeout=120\nmem_mb=0\nnproc=0\ncpu=0\n' > "$EXERCISE/exercise.cfg"

output="$("$CORE/phobos.sh" --config "$EXERCISE/exercise.cfg" -- /opt/java/openjdk/bin/java -cp "$EXERCISE/assignment" ServerProbe 2>&1)"
printf '%s\n' "$output"
echo
if grep -qF "ephemeral-server=ok read=7" <<<"$output"; then
  ok "shipped policy lets a server take a kernel-chosen port, and a client reach it"
else
  bad "shipped policy lets a server take a kernel-chosen port, and a client reach it" "$output"
fi
if grep -qF "fixed-server=denied" <<<"$output"; then
  ok "shipped policy refuses a server that names a port of its own"
else
  bad "shipped policy refuses a server that names a port of its own" "$output"
fi
if grep -qF "ephemeral-udp=ok" <<<"$output"; then
  ok "shipped policy lets a UDP socket take a kernel-chosen port, which Gradle needs for file locking"
else
  bad "shipped policy lets a UDP socket take a kernel-chosen port, which Gradle needs for file locking" "$output"
fi

output="$("$CORE/phobos.sh" -- /opt/java/openjdk/bin/java -cp "$EXERCISE/assignment" ServerProbe 2>&1)"
printf '%s\n' "$output"
echo
if grep -qF "ephemeral-server=denied" <<<"$output" && grep -qF "fixed-server=denied" <<<"$output"; then
  ok "a run given no --config drops the bind rule, so no server opens at all"
else
  bad "a run given no --config drops the bind rule, so no server opens at all" "$output"
fi

# What a JVM reads at start-up is granted file by file in the shipped Java base: eleven static or aggregate
# files of the machine. A JVM under the shipped base therefore prints no line for any of them, each is
# readable, and a neighbour of each in the same directory is still refused and reported. The six refusals
# the base leaves in place, which the JVM tolerates, are still refused and still reported. A file the
# running kernel does not have is skipped, saying so.
JVM_GRANTED=(/proc/cpuinfo /proc/meminfo /proc/stat /proc/cgroups /proc/filesystems
  /proc/sys/vm/overcommit_memory /sys/devices/system/cpu/possible /sys/devices/system/cpu/online
  /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/hpage_pmd_size /dev/random)
JVM_NEIGHBOURS=(/proc/version /proc/sys/vm/swappiness /sys/devices/system/cpu/present
  /sys/kernel/mm/transparent_hugepage/defrag /dev/zero)
PREFIX='Phobos Security Error: the program tried to illegally '
SUFFIX=' but was blocked by Phobos.'
output="$("$CORE/phobos.sh" -- /opt/java/openjdk/bin/java -version 2>&1)"
for path in "${JVM_GRANTED[@]}"; do
  if [[ ! -e "$path" ]]; then
    skip "the JVM's read of ${path}" "this kernel does not have it, so the base grants nothing there"
    continue
  fi
  if [[ "$(grep -cF "illegally read the File '${path}'" <<<"$output")" == 0 ]]; then
    ok "the JVM's start-up read of ${path} prints no line"
  else
    bad "the JVM's start-up read of ${path} prints no line" "$output"
  fi
  head_output="$("$CORE/phobos.sh" -- head -c 1 "$path" 2>&1)"
  if [[ "$(grep -c 'Permission denied' <<<"$head_output")" == 0 && "$(grep -cF "illegally read the File '${path}'" <<<"$head_output")" == 0 ]]; then
    ok "${path} is readable under the shipped base"
  else
    bad "${path} is readable under the shipped base" "$head_output"
  fi
done
for path in "${JVM_NEIGHBOURS[@]}"; do
  [[ -e "$path" ]] || { skip "a neighbour of the granted files, ${path}" "this kernel does not have it"; continue; }
  head_output="$("$CORE/phobos.sh" -- head -c 1 "$path" 2>&1)"
  if [[ "$(grep -c 'Permission denied' <<<"$head_output")" -ge 1 && "$(grep -cxF "${PREFIX}read the File '${path}'${SUFFIX}" <<<"$head_output")" == 1 ]]; then
    ok "${path}, beside the granted files, is still refused and reported"
  else
    bad "${path}, beside the granted files, is still refused and reported" "$head_output"
  fi
done
# The six the base leaves refused. Each is judged by the path the kernel resolved, so a link or /proc/self
# shows as the process's own entry, and the line is matched by the part that names the file.
refused_and_reported() {
  local label="$1"
  local fragment="$2"
  local script="$3"
  local combined
  combined="$("$CORE/phobos.sh" -- sh -c "$script" 2>&1)"
  if [[ "$(grep -c 'Permission denied' <<<"$combined")" -ge 1 ]] \
    && [[ "$(grep -cE "^${PREFIX}(read|write) the (File|Directory) .*${fragment}.*${SUFFIX}\$" <<<"$combined")" -ge 1 ]]; then
    ok "${label} is still refused and reported"
  else
    bad "${label} is still refused and reported" "$combined"
  fi
}
refused_and_reported "a write of /proc/self/coredump_filter" "coredump_filter" 'echo 1 > /proc/self/coredump_filter'
refused_and_reported "a read of /proc/mounts" "mounts" 'head -c 1 /proc/mounts'
if [[ -e /proc/net/if_inet6 ]]; then
  refused_and_reported "a read of /proc/net/if_inet6" "if_inet6" 'head -c 1 /proc/net/if_inet6'
else
  skip "a read of /proc/net/if_inet6" "this kernel has no IPv6, so the file does not exist"
fi
refused_and_reported "a read of another process's /proc/<pid>/stat" "/proc/1/stat" 'head -c 1 /proc/1/stat'
refused_and_reported "a read of /proc/self/fd" "/fd" 'ls /proc/self/fd'
if [[ -e /dev/tty ]]; then
  refused_and_reported "a write of /dev/tty" "tty" 'echo x > /dev/tty'
else
  skip "a write of /dev/tty" "this container has no /dev/tty"
fi

finish
