#!/bin/bash
# shellcheck shell=bash
# The manual of phobos-cli.sh.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh. It starts nothing
# while it is sourced.

# Prints the manual on the file descriptor named by $1. Assumes nothing.
help_text() {
  cat >&"$1" <<'PHOBOS_CLI_HELP'
phobos-cli.sh - run a command under Phobos, prune or record a reference program, build the image.

USAGE
  phobos-cli.sh [--mode host|image] [--dry-run] run [options] [--] <command> [args...]
  phobos-cli.sh [--mode host|image] [--dry-run] prune <java-gradle|java-maven|python|c-fact|r|swift|c-gcc|cpp|java-egress|all>
  phobos-cli.sh [--mode host|image] [--dry-run] record [options] <record|generate|check|diff> [args...]
  phobos-cli.sh [--mode host|image] [--dry-run] build <java|python|c-fact|r|swift|c-gcc|cpp>
  phobos-cli.sh [--mode host|image] [--dry-run]           on a terminal: the menu
  phobos-cli.sh --help

PLACES
  Inside an image (the directory /var/tmp/opt/core exists) the command starts what the image holds.
  On a host it starts Docker. --mode may confirm the place and never overrides it. --dry-run prints
  what would be started, one block per command: COMMAND, one argument per line, END.

MENU
  Called with no command while its standard input and output are a terminal, it opens a menu (it
  needs dialog) that asks for the answers of a call, runs phobos-cli.sh with exactly that call, and
  prints the call at the end. --dry-run and --mode apply to it. Without a terminal, no command is a
  usage error, so a script never waits for an answer.

run
  Starts the command under phobos.sh. Accepted in both places:
    --config <file>, -c <file>   an exercise configuration; repeatable
    --project-root <dir>         the project directory an Ares 2 policy resolves against
    --resolver <ip[:port]>       the resolver the egress broker uses for an exact host name
    --debug, -d                  the effective policy and what each layer does, on stderr
  Refused in both places, with status 2: every --no-* and -n* switch that turns a layer off, every
  --*-bin override of an enforcer, and any option not listed here. To debug with a layer off, call
  phobos.sh directly. Everything after -- (or after the first word that is not an option) is the
  command, options of its own included.
  On a host also:
    --language <java|python|c-fact|r|swift|c-gcc|cpp> the run-phase image to use (default java)
    --image <name>               a run-phase image by name; not with --language
    --exercise <dir>             required; mounted read-write as /var/tmp/testing-dir, the working
                                 directory of the command
    --network <name>             a Docker network; default none; host and container: are refused
    --memory <size>              default 8g
    --pids-limit <n>             default 1024
    --cpus <n>                   no default
  A host copies each configuration into a private directory and mounts it read-only, so that the
  command can never write one. --project-root is then relative to --exercise.

prune
  Host: runs the Compose service of the key, rebuilt first; "all" runs the seventeen jobs of the layer
  pruner in order (the eight prunes, the merge, the eight verifications) and stops at the first one
  that fails. Image: runs the layer pruner (/var/tmp/helpers/exercise_pruner/src/interface/main.py); java-egress needs
  --resolver <ip[:port]>.

record
  Runs the recording pruner, which runs the program unsandboxed: for the instructor's reference
  program only, never for a submission. On a host also --language <java|python|c-fact|r|swift|c-gcc|cpp> (default java),
  --exercise <dir> (mounted read-only) and --networked.

build
  Host only: assembles build/run-phase-context and builds the image of the language.

EXIT STATUSES
  The command's own, when it ran; 2 for a call made the wrong way; 15 (PHB-ERUNTIME) when a
  command cannot start: no Docker, a missing component, a leaked BASH_ENV or LD_PRELOAD.
  Start it without BASH_ENV, ENV, LD_PRELOAD, LD_LIBRARY_PATH and LD_AUDIT: bash and the loader
  read them before the first line, so this script can only refuse when it finds them set.
PHOBOS_CLI_HELP
}
