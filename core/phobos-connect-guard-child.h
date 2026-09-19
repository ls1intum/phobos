/*
 * The sandboxed half of the guard: it installs the seccomp filter, hands its notification
 * descriptor to the supervisor, and becomes the rest of the layer chain.
 */
#ifndef PHOBOS_CONNECT_GUARD_CHILD_H
#define PHOBOS_CONNECT_GUARD_CHILD_H

/* The child. Installs the filter, sends its notification descriptor up, then
 * becomes the rest of the chain. Never returns: it execs, or it exits. */
[[noreturn]] void run_child(int send_descriptor_to_parent, char *const command[]);

#endif
