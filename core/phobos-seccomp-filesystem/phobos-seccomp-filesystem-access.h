/*
 * What a trapped path call asks of Landlock, decoded from the kernel's copy of its arguments.
 *
 * A supervisor's filter traps the path system calls only to report them, never to decide them.
 * This module turns one notification into the objects the call names and the flags that decide
 * which Landlock right it needs, without reading the command's memory: the names themselves are
 * read later, and only for a task inside the filesystem domain.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_ACCESS_H
#define PHOBOS_SECCOMP_FILESYSTEM_ACCESS_H

#include <linux/audit.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>

/* The one native ABI this build's system call numbers belong to. A call through any other ABI is
 * never decoded as a path call, whatever its number. */
#if defined(__x86_64__)
#define REPORT_NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define REPORT_NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "the denial reporter supports x86-64 and aarch64 only"
#endif

/* The families of trapped call, each judged by its own rule (A.6.4 of the plan). */
enum access_kind {
    ACCESS_OPEN,
    ACCESS_OPEN_HOW,
    ACCESS_EXECUTE,
    ACCESS_MAKE_DIRECTORY,
    ACCESS_MAKE_NODE,
    ACCESS_REMOVE,
    ACCESS_RENAME,
    ACCESS_LINK,
    ACCESS_MAKE_SYMBOLIC_LINK,
    ACCESS_TRUNCATE,
    ACCESS_BIND,
    ACCESS_ARMING,
};

/* One name the call is about, as the command handed it over. */
struct named_object {
    int directory;          /* AT_FDCWD or the descriptor the name is relative to */
    uint64_t name_address;  /* the pointer to the name in the command's memory */
};

/* Everything about a trapped call that decides which right Landlock checks on which object. */
struct access_request {
    enum access_kind kind;
    size_t object_count;              /* 1, or 2 for rename and link */
    struct named_object objects[2];
    int open_flags;                   /* openat, open, creat */
    uint64_t open_how_address;        /* openat2: where its struct open_how lies */
    uint64_t open_how_size;           /* openat2: the size the command gave for it */
    unsigned int mode;                /* mknodat, mknod */
    unsigned int rename_flags;        /* renameat2 */
    int unlink_flags;                 /* unlinkat, and AT_REMOVEDIR for rmdir */
    int execute_flags;                /* execveat */
    int link_flags;                   /* linkat */
    uint64_t link_target_address;     /* symlinkat, symlink: where the link's target lies */
    int64_t truncate_length;          /* truncate */
    int socket_descriptor;            /* bind: the socket */
    uint32_t socket_address_length;   /* bind: object 0 points at the address, of this length */
};

/* Fills request from the trapped call's architecture, number and scalar arguments. Answers false
 * for a call through a foreign ABI or a number the reporter does not decode, which is then
 * continued silently. */
bool decode_trapped_call(const struct seccomp_data *data, struct access_request *request);

/* The calls a supervisor's filter traps to report, in one place, and how many there are. None of
 * them is a call the connect guard enforces or a call a Phobos filter refuses outright. */
extern const int REPORT_TRAPPED_CALLS[];
extern const size_t REPORT_TRAPPED_CALL_COUNT;

#endif
