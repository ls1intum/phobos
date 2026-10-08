/*
 * What the egress broker says about the connections it refuses, read by the guard.
 *
 * When a [connect] rule names a host, the guard hands every allowed connection to the broker, which
 * reads the TLS host name and refuses a connection no rule allows. The guard had already allowed it
 * by address and port, so it would never learn of the refusal; the broker therefore logs each one
 * to an anonymous pipe no path names, held only by HAProxy and the guard, and the guard prints a
 * line for it. The pipe is not a channel into the policy: nothing the broker allows or refuses
 * changes, and a line that is lost, malformed or forged only changes what is printed.
 *
 * A line is "PHB-BROKER <backend> <termination state> <hex host name, or -> <address> <port>".
 */
#ifndef PHOBOS_CONNECT_GUARD_BROKER_LOG_H
#define PHOBOS_CONNECT_GUARD_BROKER_LOG_H

#include <stddef.h>

/* The longest line the guard reads; a longer one is dropped whole. */
static constexpr size_t BROKER_LOG_LINE_MAXIMUM = 1024;

/* Parses one broker log line and reports it when it is a refusal (backend "refuse", or a
 * termination state that starts with "PR"). Ignores any other line, a malformed one and one longer
 * than BROKER_LOG_LINE_MAXIMUM. A host name is decoded from its hex and quoted like a path, because
 * the program chose it. Without one, the destination is named as an endpoint. */
void handle_broker_log_line(const char *line, size_t length);

/* Reads what the broker pipe holds without blocking and hands every complete line to
 * handle_broker_log_line, keeping an incomplete tail for the next read and dropping a line that
 * outgrows BROKER_LOG_LINE_MAXIMUM before its newline. */
void drain_broker_log(int descriptor);

/* Takes the inherited broker descriptor: makes it close-on-exec, so the guard's child and the
 * command never inherit it, and non-blocking on the open file description it shares with HAProxy,
 * so HAProxy's writes can never block. Answers false when the descriptor is not an open pipe. */
bool adopt_broker_log(int descriptor);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Forgets any line half read, so each test case starts with an empty buffer. */
void broker_log_reset_for_tests(void);
#endif

#endif
