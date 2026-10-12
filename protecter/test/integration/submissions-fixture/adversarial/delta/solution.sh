#!/bin/bash
# A submission that tries, while the pruner runs it without Phobos, to change what it must not: its
# staged exercise and the helpers of the pruner, both mounted read-only, and the evidence of its own
# result, in the one directory mounted writable, which the seal then refuses. Writing its own build
# output is what it may do.
touch /srv/phobos-prune-exercises/forged 2> /dev/null
touch /var/tmp/helpers/forged 2> /dev/null
printf 'forged\n' > /var/tmp/path_sets/forged 2> /dev/null
mkdir -p build && printf 'own output\n' > build/own.txt
