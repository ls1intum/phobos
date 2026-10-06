/*
 * What a supervisor with a sandboxed child does around its notifications: the child hands its
 * listener up over a socket pair, the supervisor passes a caller's signals on to the command and,
 * once the command has ended, reaps it and ends with its status.
 *
 * Shared by the connect guard and the report-only supervisor (core/phobos-seccomp-filesystem),
 * which links this file rather than carrying a second copy. Nothing here prints.
 */
#ifndef PHOBOS_CONNECT_GUARD_HANDOFF_H
#define PHOBOS_CONNECT_GUARD_HANDOFF_H

#include <signal.h>
#include <sys/types.h>

/* Hands one file descriptor to the supervisor over the socket pair. Answers whether it was sent. */
bool send_descriptor(int socket_descriptor, int descriptor_to_send);

/* Receives the one descriptor the child sends. Returns it, or -1 on any failure, including the
 * child exiting before it sent one (an end of file here). */
int receive_descriptor(int socket_descriptor);

/* Fills forwarded with the signals a supervisor passes on to its command (SIGTERM, SIGHUP, SIGINT
 * and SIGQUIT) and blocks them, keeping the mask from before in before. Called before the fork, so
 * the child starts with the old mask restored and the default dispositions. */
void block_forwarded_signals(sigset_t *forwarded, sigset_t *before);

/* Passes every forwarded signal the supervisor receives from now on to command. The supervisor
 * itself does not stop of them: it stays until the command is gone, to reap it and map its status. */
void forward_signals_to(pid_t command);

/* Waits for the command to end, still passing signals on while it runs, then reaps it with the
 * forwarded signals blocked and forgets it before they are let in again. Reaping frees the process
 * number for reuse, and a signal handled after that would be sent to whichever process took it. */
void reap_command(pid_t child, const sigset_t *forwarded, int *status);

/* The child's wait status, turned into an exit code the way a shell would: the command's own code,
 * or 128 plus the signal that ended it. */
int exit_code_from_status(int status);

#endif
