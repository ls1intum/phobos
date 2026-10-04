#!/usr/bin/env bash
# shellcheck shell=bash
# Passing a caller's signals on to the command a layer waits for.
#
# A component of phobos-common.sh, which sources this file after the others and is what every
# caller sources. It sets no shell option and sources nothing, so that sourcing the aggregate
# twice keeps doing exactly what it did before the split.
# shellcheck disable=SC2034

# The process a layer is waiting for, while run_forwarding_signals waits for it, and the signals that
# arrived before it existed. Empty otherwise.
PHB_SIGNAL_CHILD=""
PHB_SIGNAL_CHILD_START=""
PHB_SIGNAL_PENDING=""

# What a caller sets, for one call of run_forwarding_signals, for the child alone: the descriptor that
# becomes its standard error and the descriptors it must not inherit, see start_forwarded_command. Both
# are empty here, so that a value left in the environment by an outer run is not read as a request.
PHB_FORWARD_STDERR_FD=""
PHB_FORWARD_CLOSE_FDS=""

# Becomes the command run_forwarding_signals starts, in the subshell made for it: gives it the standard
# error named by PHB_FORWARD_STDERR_FD, closes the descriptors listed in PHB_FORWARD_CLOSE_FDS and
# replaces the subshell with it. They are set by the caller for that one call and are empty otherwise.
# They are applied here, to the child only, because a redirection on the call itself would be the
# standard error of the waiting shell as well. Both are removed from the environment first, since the
# numbers mean nothing to a Phobos run the command itself might start. Assumes it runs in that
# subshell, since it ends in exec.
start_forwarded_command() {
  local fd
  if [[ -n "${PHB_FORWARD_STDERR_FD:-}" ]]; then
    exec 2>&"$PHB_FORWARD_STDERR_FD"
  fi
  for fd in ${PHB_FORWARD_CLOSE_FDS:-}; do
    exec {fd}>&-
  done
  unset PHB_FORWARD_STDERR_FD PHB_FORWARD_CLOSE_FDS
  exec "$@"
}

# Puts into REPLY the time the process named by $1 started, as the 22nd field of its /proc entry in
# clock ticks since boot, and fails when there is no such process or /proc cannot be read. No process
# is started to do it. The command name in that file may hold spaces, brackets and even newlines, so the
# whole file is read and everything up to the last closing bracket is cut off before the fields are
# counted. Assumes Linux.
process_start_ticks() {
  local stat=""
  local -a fields
  { IFS= read -r -d '' stat < "/proc/$1/stat"; } 2>/dev/null
  [[ -n "$stat" ]] || return 1
  stat="${stat##*) }"
  read -r -a fields <<< "$stat"
  REPLY="${fields[19]:-}"
  [[ -n "$REPLY" ]]
}

# Succeeds while the process named by $1 is the one run_forwarding_signals started. A process number
# can be handed to an unrelated process once bash has reaped the child, so the start time recorded
# beside the number has to match as well. Where /proc cannot be read at all, only the number is
# checked. Assumes the start time was recorded before any signal could be forwarded.
process_is_current_child() {
  if [[ -z "$PHB_SIGNAL_CHILD_START" ]]; then
    kill -0 "$1" 2>/dev/null
    return
  fi
  process_start_ticks "$1" && [[ "$REPLY" == "$PHB_SIGNAL_CHILD_START" ]]
}

# Passes the named signal on to the process run_forwarding_signals is waiting for, or keeps it until
# there is one, with the ones that came before it. A process that has ended is not signalled, and
# neither is one that has taken over its number. Called only from the traps that function sets, so it
# assumes they are in place.
forward_signal_to_child() {
  local name="$1"
  if [[ -z "$PHB_SIGNAL_CHILD" ]]; then
    PHB_SIGNAL_PENDING="${PHB_SIGNAL_PENDING} ${name}"
    return 0
  fi
  if process_is_current_child "$PHB_SIGNAL_CHILD"; then
    kill -s "$name" "$PHB_SIGNAL_CHILD" 2>/dev/null || :
  fi
}

# Puts back the traps a caller saved for TERM, HUP, INT and QUIT, one argument for each in that order,
# each the output of trap -p for that signal alone, which is empty when it had none. A signal without
# a saved trap goes back to its default, and one with a trap is given it in a single step, so a signal
# the caller ignored is never exposed to its default action in between.
restore_signal_traps() {
  local saved
  local name
  local index=0
  for name in TERM HUP INT QUIT; do
    index=$(( index + 1 ))
    saved="${!index}"
    if [[ -z "$saved" ]]; then
      trap - "$name"
    else
      eval "$saved"
    fi
  done
}

# Runs a command as a child of this shell, waits for it and answers its status, and passes SIGTERM,
# SIGHUP, SIGINT and SIGQUIT sent to this shell on to it while it runs. A shell that waits for a
# foreground child does not act on a trapped signal until that child ends, and one that has no trap
# dies of it and leaves the child running, so a caller that cancelled a run would either wait for
# the command to finish or lose the layers that clean up after it. Standard input stays the
# child's: a background command would otherwise be given /dev/null. The child starts with the four
# signals at their default action, as the layers' own subshells did, and this shell's traps for them
# are put back when the child has gone, so a layer that ignores SIGTERM goes on ignoring it while it
# reports and cleans up. This shell does not block in wait while the child runs: a signal that
# arrives together with the child's end can leave bash 5.2 waiting for a child it has already
# reaped, which held every layer above the command until GNU timeout's kill-after. It watches the
# child every PHB_SIGNAL_POLL_SECONDS with sleep, which is an external command on purpose: bash's
# read with a timeout is not safe to nest, and the trap's own read, in process_start_ticks,
# cancelled the timer of the timed read it interrupted, so the poll never woke. It calls wait only once the child is gone, which then
# answers at once with the status bash kept; a wait after the child is gone has not been seen to
# block. The child is told apart
# from a process that took over its number by its start time. Between the check and the kill there
# remains the window every kill by number has, as GNU timeout's own does, and it is narrower than a
# poll.
# Assumes bash, and that it is called in the shell that has to forward, never in a command
# substitution, and with the errexit option off or tolerated by the caller.
run_forwarding_signals() {
  local saved_term
  local saved_hup
  local saved_int
  local saved_quit
  local child
  local status=0
  local pending
  saved_term="$(trap -p TERM)"
  saved_hup="$(trap -p HUP)"
  saved_int="$(trap -p INT)"
  saved_quit="$(trap -p QUIT)"
  PHB_SIGNAL_CHILD=""
  PHB_SIGNAL_PENDING=""
  trap 'forward_signal_to_child TERM' TERM
  trap 'forward_signal_to_child HUP' HUP
  trap 'forward_signal_to_child INT' INT
  trap 'forward_signal_to_child QUIT' QUIT
  ( trap - TERM HUP INT QUIT; start_forwarded_command "$@" ) <&0 &
  child=$!
  PHB_SIGNAL_CHILD_START=""
  if process_start_ticks "$$"; then
    PHB_SIGNAL_CHILD_START="ended"
    if process_start_ticks "$child"; then
      PHB_SIGNAL_CHILD_START="$REPLY"
    fi
  fi
  PHB_SIGNAL_CHILD="$child"
  for pending in $PHB_SIGNAL_PENDING; do
    forward_signal_to_child "$pending"
  done
  while process_is_current_child "$child"; do
    sleep "${PHB_SIGNAL_POLL_SECONDS}"
  done
  wait "$child" || status=$?
  PHB_SIGNAL_CHILD=""
  PHB_SIGNAL_CHILD_START=""
  restore_signal_traps "$saved_term" "$saved_hup" "$saved_int" "$saved_quit"
  return "$status"
}
