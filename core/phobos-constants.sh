#!/usr/bin/env bash
# shellcheck shell=bash
# The numbers the Phobos shell scripts share, each named once. phobos-common.sh sources this
# file, and the test suites source it on its own, so it sets no shell option and only assigns
# plain variables: sourcing it twice, or into a shell running without -e, changes nothing else.
# Every variable here is read by the scripts that source it, never in this file.
# shellcheck disable=SC2034

# The statuses a Phobos run ends with when Phobos itself stops it. They are an external
# contract, read by whatever grades the run, and tests/cli_flags.sh pins each one to its value.
PHB_EPOLICY=11
PHB_ETIMEOUT=14
PHB_ERUNTIME=15
# The status a script ends with when it was called the wrong way.
PHB_EXIT_USAGE=2
# The status phobos-landlock and the connect guard end with when they refuse to set up the
# sandbox; the C sources name it EXIT_CODE_POLICY_ERROR and EXIT_CODE_SETUP_ERROR.
PHB_ENFORCER_REFUSED_EXIT=125

# GNU timeout's own exit statuses: the command ran past its limit and was stopped by the
# SIGTERM, or it ignored the SIGTERM and the --kill-after escalation's SIGKILL ended it
# (128 + 9). A command can end with either status on its own, so neither alone is a timeout.
PHB_TIMEOUT_EXPIRED_EXIT=124
PHB_TIMEOUT_KILLED_EXIT=137
# How long GNU timeout lets a command ignore SIGTERM before it sends SIGKILL.
PHB_KILL_AFTER_SECONDS=5

# How long the filesystem layer waits, after the command has ended, for the denial counts. A
# process the command left behind can keep its stderr, and so the counter, alive; the layer
# then reports no counts rather than wait for it. Kept below PHB_KILL_AFTER_SECONDS, so GNU
# timeout never escalates to SIGKILL while the layer is still waiting here.
PHB_DENIAL_COUNT_GRACE_SECONDS=2
# The counter's own limits. It runs outside the command's rlimits, so without these a single
# endless stderr line could grow it without bound. A counter that hits them dies, and the run
# then reports no counts; the command's output is never affected.
PHB_DENIAL_COUNTER_MEMORY_KB=65536
PHB_DENIAL_COUNTER_CPU_SECONDS=60

# Units. ulimit takes memory in kilobytes and file sizes in 1024-byte blocks, while a policy
# names both in megabytes.
PHB_MILLISECONDS_PER_SECOND=1000
PHB_MICROSECONDS_PER_MILLISECOND=1000
PHB_KILOBYTES_PER_MEGABYTE=1024
# The largest megabyte value whose kilobytes, or 1024-byte blocks, still fit the shell's signed
# 64-bit arithmetic: (2^63 - 1) / 1024. A larger one would wrap to a small or negative limit.
PHB_LARGEST_MEGABYTES=8796093022207

# The highest TCP port there is; the lowest is 1.
PHB_HIGHEST_PORT=65535
# An unbracketed [connect] target with at least this many colons is an IPv6 address, whose own
# colons leave no room for a ":port".
PHB_IPV6_MINIMUM_COLONS=2
