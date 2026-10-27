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
 * A line is "PHB-BROKER <backend> <termination state> <hex host name, or -> <address> <port> <hex
 * token, or ->", and the broker writes one for every connection, refused or not.
 *
 * The broker decides and logs on its own schedule, so a refusal can be logged after the command has
 * ended. To read that line too, every connection the guard hands over carries a token in its PROXY
 * header, a sequence number and sixteen random bytes drawn for that connection alone, and the broker
 * logs it back. Once supervision is over the guard reads on until every token it handed over has
 * come back, within BROKER_LOG_GRACE_MILLISECONDS. A token is never derived from another, so one
 * read from the pipe tells nothing about the next, and a stream the command makes on its own through
 * the broker's port carries no token the guard issued.
 */
#ifndef PHOBOS_CONNECT_GUARD_BROKER_LOG_H
#define PHOBOS_CONNECT_GUARD_BROKER_LOG_H

#include <stddef.h>
#include <stdint.h>

/* The longest line the guard reads; a longer one is dropped whole. */
static constexpr size_t BROKER_LOG_LINE_MAXIMUM = 1024;

/* The bytes of a handoff's token: an eight-byte sequence number, big-endian, then sixteen random bytes. */
static constexpr size_t BROKER_TOKEN_SIZE = 24;

/* How long the guard reads on after supervision for tokens that have not come back. Every refusal the
 * guard words is decided by the broker as soon as the client's bytes or its end arrive, and once
 * supervision is over every socket of the command is closed, so such a line comes within
 * milliseconds; the grace bounds the rest: a line lost to a full pipe, an allowed connection still
 * resolving or connecting onward, a broker that died. It is below the five seconds GNU timeout gives a
 * command between its TERM and its SIGKILL, though a run ended by a signal does not wait at all. */
static constexpr int BROKER_LOG_GRACE_MILLISECONDS = 2000;

/* Parses one broker log line and reports it when it is a refusal (backend "refuse", or a
 * termination state that starts with "PR"). Ignores any other line, a malformed one and one longer
 * than BROKER_LOG_LINE_MAXIMUM. A host name is decoded from its hex and quoted like a path, because
 * the program chose it. Without one, the destination is named as an endpoint. A well-formed line
 * whose token is one the guard handed over and has not seen yet counts that handoff as answered,
 * whether or not the line is a refusal. */
void handle_broker_log_line(const char *line, size_t length);

/* Reads what the broker pipe holds without blocking, at most a bounded number of reads, and hands
 * every complete line to handle_broker_log_line, keeping an incomplete tail for the next read and
 * dropping a line that outgrows BROKER_LOG_LINE_MAXIMUM before its newline. Answers whether the pipe
 * may still hold bytes, because the bound was reached before a read came back empty. */
bool drain_broker_log(int descriptor);

/* Draws the token for the next handoff into token. Answers false, for this and every later handoff
 * of the run, once the guard can no longer keep count: random bytes it could not draw, room it could
 * not get, or more handoffs than it keeps. The handoff is then made without a token, and the wait at
 * the end of the run lasts the whole grace. */
bool reserve_broker_token(uint8_t token[BROKER_TOKEN_SIZE]);

/* Records that the header carrying the token reserved last was sent whole, so the broker holds a
 * stream for it that will be logged. A token reserved and never handed is never waited for. */
void hand_broker_token(void);

/* Reads the pipe after supervision until every token handed over has come back, the grace has run
 * out, a forwarded signal has arrived, or the pipe has failed. Reads once, bounded, before it waits and
 * once after, so a line already waiting is never left behind. The forwarded signals are blocked while
 * it decides whether to wait, and given back as they were when it is done. */
void settle_broker_log(int descriptor);

/* Takes the inherited broker descriptor: makes it close-on-exec, so the guard's child and the
 * command never inherit it, and non-blocking on the open file description it shares with HAProxy,
 * so HAProxy's writes can never block. Answers false when the descriptor is not an open pipe. */
bool adopt_broker_log(int descriptor);

#ifdef PHOBOS_CONNECT_GUARD_UNIT_TEST
/* Forgets any line half read and every token, so each test case starts with an empty buffer and a
 * run that has handed nothing over. */
void broker_log_reset_for_tests(void);

/* Shortens the grace, so a case can let it run out without waiting two seconds. */
void broker_log_grace_for_tests(int milliseconds);

/* Lowers the number of handoffs the guard keeps count of, so a case can reach it. */
void broker_token_limit_for_tests(uint64_t limit);
#endif

#endif
