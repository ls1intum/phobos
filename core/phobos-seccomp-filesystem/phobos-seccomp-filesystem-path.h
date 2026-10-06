/*
 * Reading what a trapped call names out of the command, and resolving it the way Landlock sees it.
 *
 * Every read from the command is followed by SECCOMP_IOCTL_NOTIF_ID_VALID, so a process number the
 * kernel has recycled since the notification can never make the supervisor read a stranger's
 * memory or working directory into a line. A read that fails, or a notification that has
 * vanished, answers false, and the caller then reports nothing: this module errs towards a
 * missing line, never a wrong one.
 */
#ifndef PHOBOS_SECCOMP_FILESYSTEM_PATH_H
#define PHOBOS_SECCOMP_FILESYSTEM_PATH_H

#include "phobos-seccomp-filesystem-access.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The task a notification came from, and how to ask whether that notification is still live. */
struct task_view {
    pid_t pid;
    int notify_descriptor;
    uint64_t id;
    const char *status;  /* /proc/<pid>/status, read once for the notification */
};

/* Whether the notification is still pending, so what was read for it belongs to its task. */
bool notification_still_valid(const struct task_view *task);

/* Reads exactly size bytes at address out of the command. */
bool read_command_bytes(const struct task_view *task, uint64_t address, void *out, size_t size);

/* Reads a NUL-terminated name of fewer than size bytes out of the command, page by page, and
 * makes it absolute against /proc/<pid>/cwd or /proc/<pid>/fd/<directory>. Answers false for an
 * empty name, a name too long, a directory that reads back as deleted or as not reachable from
 * the root, and a vanished notification. */
bool read_absolute_name(const struct task_view *task, const struct named_object *object, char *out,
                        size_t size);

/* Makes a name absolute against the task's working directory or the directory a descriptor of
 * the task names, with the same refusals as read_absolute_name. */
bool make_absolute(const struct task_view *task, int directory, const char *name, char *out,
                   size_t size);

/* Resolves a name the way Landlock sees it. anchor receives the path whose ancestors are walked:
 * the object itself (parent == false), or its resolved parent directory (parent == true). shown
 * receives the path the line names: the resolved object, or the resolved parent joined with the
 * last name as the program gave it. The two differ only for a call that creates or removes a name.
 * Answers false when the path or its parent does not resolve, and, with parent, when the last name
 * is empty, "." or "..". */
bool resolve_for_landlock(const char *absolute, bool parent, char *anchor, size_t anchor_size,
                          char *shown, size_t shown_size);

/* Reads a whole small file, such as one under /proc, NUL-terminated. Answers false when it cannot
 * be opened or read, or does not fit. */
bool read_small_file(const char *path, char *out, size_t size);

#endif
