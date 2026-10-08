#!/usr/bin/env bash
# Spike only. Puts the exercise state the session expects in place: a work directory holding a
# file the session deletes and a shell script it runs. Called before a recording and before a
# replay, so both start from the same state, as a grading container starts from the image.
set -euo pipefail

mkdir -p /var/tmp/testing-dir
printf 'old\n' > /var/tmp/testing-dir/old.txt
printf '#!/bin/sh\ncat /etc/os-release > /dev/null\necho tool\n' > /var/tmp/testing-dir/tool.sh
chmod +x /var/tmp/testing-dir/tool.sh
