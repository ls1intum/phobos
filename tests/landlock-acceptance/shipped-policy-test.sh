#!/usr/bin/env bash
# Runs the SHIPPED Java policy end to end, in both directions.
#
# Every other acceptance script swaps in its own tight test policy, so no suite ever ran
# core/config/BaseLanguage-java.cfg, the policy an exercise actually gets. This one applies
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

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
EXERCISE=/var/tmp/testing-dir

pass=0
fail=0
ok()  { printf 'ok    %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }

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

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
