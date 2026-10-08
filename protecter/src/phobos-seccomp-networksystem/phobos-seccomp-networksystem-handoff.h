/*
 * What a supervisor with a sandboxed child does around its notifications: the child hands its
 * listener up over a socket pair, the supervisor passes a caller's signals on to the command and,
 * once the command has ended, reaps it and ends with its status.
 *
 * Shared by the connect guard and the report-only supervisor (protecter/src/phobos-seccomp-filesystem),
 * which links this file rather than carrying a second copy. Nothing here prints.
 */
#ifndef PHOBOS_CONNECT_GUARD_HANDOFF_H
#define PHOBOS_CONNECT_GUARD_HANDOFF_H

#include <signal.h>
#include <sys/types.h>

#include <linux/seccomp.h>

/* The status a supervisor ends with when its command ran but its exit status could not be read
 * (PHB-ESTATUS, as phobos-constants.sh names it). Ending with 0 then would grade a command that
 * failed as one that passed, so the run fails closed with a status of its own instead. */
static constexpr int EXIT_CODE_STATUS_UNREAD = 16;

/* Hands one file descriptor to the supervisor over the socket pair. Answers whether it was sent. */
bool send_descriptor(int socket_descriptor, int descriptor_to_send);

/* Receives the one descriptor the child sends. Returns it, or -1 on any failure, including the
 * child exiting before it sent one (an end of file here). */
int receive_descriptor(int socket_descriptor);

/* Fills forwarded with the signals a supervisor passes on to its command (SIGTERM, SIGHUP, SIGINT
 * and SIGQUIT) and blocks them, keeping the mask from before in before. Called before the fork, so
 * the child starts with the old mask restored and the default dispositions. */
void block_forwarded_signals(sigset_t *forwarded, sigset_t *before);

/* Gives SIGCHLD its default disposition in the supervisor, keeping the one it inherited in
 * inherited. A caller that ignores SIGCHLD hands that on across exec, and an ignored SIGCHLD makes
 * the kernel reap every child by itself, so the supervisor could never read its command's status.
 * Called before the fork. */
void take_default_child_signal(struct sigaction *inherited);

/* Gives SIGCHLD back the disposition the supervisor inherited, in the child before it becomes the
 * command, so the command starts with what its caller gave it. */
void restore_child_signal(const struct sigaction *inherited);

/* Passes every forwarded signal the supervisor receives from now on to command. The supervisor
 * itself does not stop of them: it stays until the command is gone, to reap it and map its status. */
void forward_signals_to(pid_t command);

/* Waits for the command to end, still passing signals on while it runs, then reaps it with the
 * forwarded signals blocked and forgets it before they are let in again. Reaping frees the process
 * number for reuse, and a signal handled after that would be sent to whichever process took it.
 * Answers whether status holds the command's wait status: false when it could not be read (the
 * command was reaped by someone else, ECHILD), and the caller then ends with
 * EXIT_CODE_STATUS_UNREAD rather than with any status of its own making. */
bool reap_command(pid_t child, const sigset_t *forwarded, int *status);

/* Sends the response to one notification, and sends it again for as long as a signal interrupts
 * the send. The kernel takes the filter's lock interruptibly and then fails with EINTR; the
 * notification has already been received, so it is never offered a second time, and a response
 * given up on would leave the trapped call waiting until its task is signalled. Answers whether it
 * was delivered; a send that finds the task gone fails with ENOENT, which concerns nobody. */
bool send_notification_response(int notify_descriptor, struct seccomp_notif_resp *response);

/* The child's wait status, turned into an exit code the way a shell would: the command's own code,
 * or 128 plus the signal that ended it. */
int exit_code_from_status(int status);

#endif
