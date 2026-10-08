#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-access.h"

#include "../phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.h"

#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>

#ifdef __NR_open
/* The flags creat(2) stands for. */
static constexpr int CREAT_FLAGS = O_WRONLY | O_CREAT | O_TRUNC;
#endif

const int REPORT_TRAPPED_CALLS[] = {
#ifdef __NR_open
    __NR_open,
    __NR_creat,
    __NR_mkdir,
    __NR_rmdir,
    __NR_unlink,
    __NR_rename,
    __NR_link,
    __NR_symlink,
    __NR_mknod,
#endif
#ifdef __NR_renameat
    __NR_renameat,
#endif
    __NR_openat,
    __NR_openat2,
    __NR_execve,
    __NR_execveat,
    __NR_mkdirat,
    __NR_mknodat,
    __NR_unlinkat,
    __NR_renameat2,
    __NR_linkat,
    __NR_symlinkat,
    __NR_truncate,
    __NR_bind,
    SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF,
};
const size_t REPORT_TRAPPED_CALL_COUNT = sizeof(REPORT_TRAPPED_CALLS) / sizeof(REPORT_TRAPPED_CALLS[0]);

const int REPORT_NETWORK_TRAPPED_CALLS[] = {
    __NR_bind,
    SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF,
};
const size_t REPORT_NETWORK_TRAPPED_CALL_COUNT =
    sizeof(REPORT_NETWORK_TRAPPED_CALLS) / sizeof(REPORT_NETWORK_TRAPPED_CALLS[0]);

/* Names one object of the request. */
static void name_object(struct access_request *request, size_t index, uint64_t directory,
                        uint64_t name_address) {
    request->objects[index].directory = (int)directory;
    request->objects[index].name_address = name_address;
    if (request->object_count < index + 1) {
        request->object_count = index + 1;
    }
}

/* Decodes the calls the legacy x86-64 ABI keeps beside their *at forms. Every name in them is
 * relative to the working directory. Answers false for any other number. */
static bool decode_legacy_call(const struct seccomp_data *data, struct access_request *request) {
#ifdef __NR_open
    const uint64_t working_directory = (uint64_t)(int64_t)AT_FDCWD;
    switch (data->nr) {
    case __NR_open:
        request->kind = ACCESS_OPEN;
        name_object(request, 0, working_directory, data->args[0]);
        request->open_flags = (int)data->args[1];
        return true;
    case __NR_creat:
        request->kind = ACCESS_OPEN;
        name_object(request, 0, working_directory, data->args[0]);
        request->open_flags = CREAT_FLAGS;
        return true;
    case __NR_mkdir:
        request->kind = ACCESS_MAKE_DIRECTORY;
        name_object(request, 0, working_directory, data->args[0]);
        return true;
    case __NR_mknod:
        request->kind = ACCESS_MAKE_NODE;
        name_object(request, 0, working_directory, data->args[0]);
        request->mode = (unsigned int)data->args[1];
        return true;
    case __NR_unlink:
        request->kind = ACCESS_REMOVE;
        name_object(request, 0, working_directory, data->args[0]);
        return true;
    case __NR_rmdir:
        request->kind = ACCESS_REMOVE;
        name_object(request, 0, working_directory, data->args[0]);
        request->unlink_flags = AT_REMOVEDIR;
        return true;
    case __NR_rename:
        request->kind = ACCESS_RENAME;
        name_object(request, 0, working_directory, data->args[0]);
        name_object(request, 1, working_directory, data->args[1]);
        return true;
    case __NR_link:
        request->kind = ACCESS_LINK;
        name_object(request, 0, working_directory, data->args[0]);
        name_object(request, 1, working_directory, data->args[1]);
        return true;
    case __NR_symlink:
        request->kind = ACCESS_MAKE_SYMBOLIC_LINK;
        name_object(request, 0, working_directory, data->args[1]);
        request->link_target_address = data->args[0];
        return true;
    default:
        return false;
    }
#else
    (void)data;
    (void)request;
    return false;
#endif
}

/* Decodes the two-name calls, rename and link, in their *at forms. Answers false for any other
 * number. */
static bool decode_two_name_call(const struct seccomp_data *data, struct access_request *request) {
    switch (data->nr) {
#ifdef __NR_renameat
    case __NR_renameat:
        request->kind = ACCESS_RENAME;
        name_object(request, 0, data->args[0], data->args[1]);
        name_object(request, 1, data->args[2], data->args[3]);
        return true;
#endif
    case __NR_renameat2:
        request->kind = ACCESS_RENAME;
        name_object(request, 0, data->args[0], data->args[1]);
        name_object(request, 1, data->args[2], data->args[3]);
        request->rename_flags = (unsigned int)data->args[4];
        return true;
    case __NR_linkat:
        request->kind = ACCESS_LINK;
        name_object(request, 0, data->args[0], data->args[1]);
        name_object(request, 1, data->args[2], data->args[3]);
        request->link_flags = (int)data->args[4];
        return true;
    default:
        return decode_legacy_call(data, request);
    }
}

bool decode_trapped_call(const struct seccomp_data *data, struct access_request *request) {
    memset(request, 0, sizeof(*request));
    if (data->arch != REPORT_NATIVE_AUDIT_ARCH) {
        return false;
    }
    switch (data->nr) {
    case __NR_openat:
        request->kind = ACCESS_OPEN;
        name_object(request, 0, data->args[0], data->args[1]);
        request->open_flags = (int)data->args[2];
        return true;
    case __NR_openat2:
        request->kind = ACCESS_OPEN_HOW;
        name_object(request, 0, data->args[0], data->args[1]);
        request->open_how_address = data->args[2];
        request->open_how_size = data->args[3];
        return true;
    case __NR_execve:
        request->kind = ACCESS_EXECUTE;
        name_object(request, 0, (uint64_t)(int64_t)AT_FDCWD, data->args[0]);
        return true;
    case __NR_execveat:
        request->kind = ACCESS_EXECUTE;
        name_object(request, 0, data->args[0], data->args[1]);
        request->execute_flags = (int)data->args[4];
        return true;
    case __NR_mkdirat:
        request->kind = ACCESS_MAKE_DIRECTORY;
        name_object(request, 0, data->args[0], data->args[1]);
        return true;
    case __NR_mknodat:
        request->kind = ACCESS_MAKE_NODE;
        name_object(request, 0, data->args[0], data->args[1]);
        request->mode = (unsigned int)data->args[2];
        return true;
    case __NR_unlinkat:
        request->kind = ACCESS_REMOVE;
        name_object(request, 0, data->args[0], data->args[1]);
        request->unlink_flags = (int)data->args[2];
        return true;
    case __NR_symlinkat:
        request->kind = ACCESS_MAKE_SYMBOLIC_LINK;
        name_object(request, 0, data->args[1], data->args[2]);
        request->link_target_address = data->args[0];
        return true;
    case __NR_truncate:
        request->kind = ACCESS_TRUNCATE;
        name_object(request, 0, (uint64_t)(int64_t)AT_FDCWD, data->args[0]);
        request->truncate_length = (int64_t)data->args[1];
        return true;
    case __NR_bind:
        request->kind = ACCESS_BIND;
        request->socket_descriptor = (int)data->args[0];
        name_object(request, 0, (uint64_t)(int64_t)AT_FDCWD, data->args[1]);
        request->socket_address_length = (uint32_t)data->args[2];
        return true;
    case SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF:
        request->kind = ACCESS_ARMING;
        return true;
    default:
        return decode_two_name_call(data, request);
    }
}
