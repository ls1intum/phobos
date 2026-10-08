#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-refusals.h"

#include "phobos-seccomp-filesystem-access.h"

#include "../phobos-seccomp-networksystem/phobos-seccomp-networksystem-handoff.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

/* The only response this file ever sends, but for the notification's id: the call fails with
 * EACCES, exactly as the filter's errno refused it before refusals became notifications. */
static const struct seccomp_notif_resp REFUSAL = {.id = 0, .val = 0, .error = -EACCES, .flags = 0};

/* Room for "foreign ABI 0x<arch> system call <number>". */
static constexpr size_t INTERFACE_NAME_LENGTH = 64;

/* Whether a native number is one of the calls the filters refuse outright. */
static bool refused_native_call(int number) {
    switch (number) {
    case __NR_io_uring_setup:
    case __NR_io_uring_enter:
    case __NR_io_uring_register:
    case __NR_setsid:
    case __NR_setpgid:
        return true;
    default:
        return false;
    }
}

/* Whether a native-ABI number is in fact an x32 one. */
static bool x32_number(int number) {
#ifdef __X32_SYSCALL_BIT
    return ((unsigned int)number & __X32_SYSCALL_BIT) != 0;
#else
    (void)number;
    return false;
#endif
}

bool is_filter_refusal(const struct seccomp_data *data) {
    if (data->arch != REPORT_NATIVE_AUDIT_ARCH) {
        return true;
    }
    return x32_number(data->nr) || refused_native_call(data->nr);
}

/* Names the foreign interface a call came through and its number in that interface: i386, x32,
 * or any other arch by its audit number. */
static void name_foreign_interface(const struct seccomp_data *data, char *out, size_t size) {
    if (data->arch == AUDIT_ARCH_I386) {
        snprintf(out, size, "i386 system call %d", data->nr);
    } else if (data->arch != REPORT_NATIVE_AUDIT_ARCH) {
        snprintf(out, size, "foreign ABI 0x%x system call %d", data->arch, data->nr);
    } else {
#ifdef __X32_SYSCALL_BIT
        snprintf(out, size, "x32 system call %u", (unsigned int)data->nr & ~__X32_SYSCALL_BIT);
#endif
    }
}

/* Reports one refused call with the wording of A.6.2. */
static void report_refusal(const struct seccomp_data *data, enum report_layer layer) {
    char interface[INTERFACE_NAME_LENGTH];
    if (data->arch != REPORT_NATIVE_AUDIT_ARCH || x32_number(data->nr)) {
        name_foreign_interface(data, interface, sizeof(interface));
        report_blocked(layer, "use", "Kernel Interface", interface, false, NULL);
    } else if (data->nr == __NR_setsid) {
        report_blocked(layer, "leave", "Session", "", false, NULL);
    } else if (data->nr == __NR_setpgid) {
        report_blocked(layer, "leave", "Process Group", "", false, NULL);
    } else {
        report_blocked(layer, "use", "Kernel Interface", "io_uring", false, NULL);
    }
}

void answer_filter_refusal(int notify_descriptor, const struct seccomp_notif *request,
                           struct seccomp_notif_resp *response, enum report_layer layer) {
    memcpy(response, &REFUSAL, sizeof(REFUSAL));
    response->id = request->id;
    (void)send_notification_response(notify_descriptor, response);
    report_refusal(&request->data, layer);
}
