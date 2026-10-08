#!/bin/bash
# shellcheck shell=bash
# The numbers the Phobos shell scripts share, each named once. phobos-common.sh sources this
# file, and the test suites source it on its own, so it sets no shell option and only assigns
# plain variables: sourcing it twice, or into a shell running without -e, changes nothing else.
# Every variable here is read by the scripts that source it, never in this file.
# shellcheck disable=SC2034

# The statuses a Phobos run ends with when Phobos itself stops it, or cannot say how the command
# ended. They are an external contract, read by whatever grades the run, and
# protecter/test/integration/cli_flags.sh pins each one to its value.
PHB_EPOLICY=11
PHB_ETIMEOUT=14
PHB_ERUNTIME=15
# The command ran but its exit status could not be read, so the run cannot say whether it
# succeeded; the connect guard and the report-only supervisor end with it rather than with 0.
# The C sources name it EXIT_CODE_STATUS_UNREAD.
PHB_ESTATUS=16
# The status a script ends with when it was called the wrong way.
PHB_EXIT_USAGE=2
# The status phobos-landlock-filesystem-and-networksystem and the connect guard end with when they refuse to set up the
# sandbox; the C sources name it EXIT_CODE_POLICY_ERROR and EXIT_CODE_SETUP_ERROR.
PHB_ENFORCER_REFUSED_EXIT=125

# GNU timeout's own exit statuses: the command ran past its limit and was stopped by the
# SIGTERM, or it ignored the SIGTERM and the --kill-after escalation's SIGKILL ended it
# (128 + 9). A command can end with either status on its own, so neither alone is a timeout.
PHB_TIMEOUT_EXPIRED_EXIT=124
PHB_TIMEOUT_KILLED_EXIT=137
# How long GNU timeout lets a command ignore SIGTERM before it sends SIGKILL.
PHB_KILL_AFTER_SECONDS=5
# How often a layer looks whether the command it waits for has ended, in seconds. It looks rather than
# blocks in wait, see run_forwarding_signals.
PHB_SIGNAL_POLL_SECONDS=0.1

# The exit statuses of a command ended by the signal of a resource limit it was given: 128 plus
# SIGXFSZ (25) for the file size limit, and 128 plus SIGKILL (9) or SIGXCPU (24) for the CPU limit,
# which ends a command with SIGKILL when its soft and hard limit are the same, on x86-64 and aarch64.
PHB_STATUS_SIGKILL=137
PHB_STATUS_SIGXCPU=152
PHB_STATUS_SIGXFSZ=153
# The processor time /proc counts in, per second, on every architecture Phobos supports, and the
# places of the waited-for children's user and system time among the fields of /proc/<pid>/stat
# after its command name, which is where the fields numbered 3 and up begin.
PHB_CLOCK_TICKS_PER_SECOND=100
PHB_STAT_CUTIME_INDEX=13
PHB_STAT_CSTIME_INDEX=14
# How far below the limit the waited-for children's time may be and still count as having reached it.
# The kernel ends a process when its tick-sampled processor time reaches the limit, while /proc reports
# the precise run time, split into user and system time and truncated twice, so a process killed at the
# limit shows up to a scheduler tick or two less. A tenth of a second covers that at every tick rate.
PHB_CPU_LIMIT_SLACK_TICKS=10

# What a run is bounded by when no cfg names a value. They are a fallback, never a cap: a cfg
# that names a larger value wins, and a cfg that names zero switches that limit off and wins
# over any of these. Before them, a policy without a [limits] section ran unbounded, and no
# shipped Base*.cfg carries one.
#
# The wall-clock bound on a run, in seconds.
PHB_DEFAULT_TIMEOUT_SECONDS=600
# Applied as `ulimit -v`, which is the virtual address space rather than the resident set. A
# 64-bit JVM reserves far more address space at startup than it ever makes resident, so a
# value near the real memory of the machine would stop every Java run before main().
PHB_DEFAULT_LIMIT_MEM_MB=8192
# Applied as `ulimit -u`, which the kernel counts per real user id rather than per process
# tree, so this bounds the grading user rather than the command alone.
PHB_DEFAULT_LIMIT_NPROC=256
PHB_DEFAULT_LIMIT_NOFILE=1024
# Applied as `ulimit -f`, so it truncates any single file the command writes, build output
# included, rather than bounding the total it writes.
PHB_DEFAULT_LIMIT_FSIZE_MB=256
# Applied as `ulimit -t`, which is cumulative CPU seconds across every thread, so a parallel
# build spends it several times faster than the wall-clock timeout above.
PHB_DEFAULT_LIMIT_CPU=600

# Units. ulimit takes memory in kilobytes and file sizes in 1024-byte blocks, while a policy
# names both in megabytes.
PHB_MILLISECONDS_PER_SECOND=1000
PHB_MICROSECONDS_PER_MILLISECOND=1000
PHB_KILOBYTES_PER_MEGABYTE=1024
# The largest megabyte value whose kilobytes, or 1024-byte blocks, still fit the shell's signed
# 64-bit arithmetic: (2^63 - 1) / 1024. A larger one would wrap to a small or negative limit.
PHB_LARGEST_MEGABYTES=8796093022207
# The most digits a resource limit may have, and the most a timeout may have in its whole seconds. Bash
# arithmetic is 64 bits wide and wraps without a word, so a longer number would be read as another one:
# a limit of 2^64 plus five as five, one of 2^64 as zero, which switches the limit off. Eighteen digits
# stay below 2^63, and a timeout of fifteen digits of seconds is below 2^63 once it is in milliseconds.
PHB_LARGEST_LIMIT_DIGITS=18
PHB_LARGEST_TIMEOUT_SECOND_DIGITS=15

# The highest TCP port there is; the lowest is 1.
PHB_HIGHEST_PORT=65535
# An unbracketed [connect] target with at least this many colons is an IPv6 address, whose own
# colons leave no room for a ":port".
PHB_IPV6_MINIMUM_COLONS=2

# The most rules the connect guard keeps. It drops every row after this many, quietly, so a rules
# file the network layer has grown by expanding host names is refused when it would pass this. Kept
# equal to MAXIMUM_RULES in phobos-seccomp-networksystem-rules.h, which a test compares.
PHB_GUARD_RULES_MAXIMUM=256
