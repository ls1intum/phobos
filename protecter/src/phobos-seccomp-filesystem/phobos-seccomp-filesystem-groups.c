#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-groups.h"

#include "phobos-seccomp-filesystem-access.h"
#include "phobos-seccomp-filesystem-path.h"

#include "../phobos-seccomp-networksystem/phobos-seccomp-networksystem-handoff.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ---------------------------------------------------------------------------------- the ledger */

struct ledger_entry {
    bool used;
    pid_t process;
    unsigned long long start;
    pid_t group;
    pid_t session;
};

/* The virtual ids of a process: the ones its own record or its nearest ancestor's gives it, or none. */
struct virtual_ids {
    bool known;
    bool incomplete;
    pid_t group;
    pid_t session;
};

static struct ledger_entry ledger[GROUP_LEDGER_CAPACITY];
static bool enabled = false;
static const struct process_table *table = nullptr;

static const struct ledger_entry *entry_of(const struct process_view *view) {
    for (size_t slot = 0; slot < GROUP_LEDGER_CAPACITY; slot++) {
        if (ledger[slot].used && ledger[slot].process == view->process && ledger[slot].start == view->start) {
            return &ledger[slot];
        }
    }
    return nullptr;
}

/* Frees the records of processes that are gone or were replaced by another with the same number. */
static void purge_ledger(void) {
    for (size_t slot = 0; slot < GROUP_LEDGER_CAPACITY; slot++) {
        struct process_view view;
        if (ledger[slot].used
            && (!table->read(ledger[slot].process, &view) || view.start != ledger[slot].start)) {
            ledger[slot].used = false;
        }
    }
}

/* Records the virtual ids of a process, replacing its own record when it has one. False when the ledger is full. */
static bool record_ids(const struct process_view *view, pid_t group, pid_t session) {
    struct ledger_entry *free_slot = nullptr;
    for (size_t slot = 0; slot < GROUP_LEDGER_CAPACITY; slot++) {
        if (ledger[slot].used && ledger[slot].process == view->process && ledger[slot].start == view->start) {
            ledger[slot].group = group;
            ledger[slot].session = session;
            return true;
        }
        if (!ledger[slot].used && free_slot == nullptr) {
            free_slot = &ledger[slot];
        }
    }
    if (free_slot == nullptr) {
        purge_ledger();
        for (size_t slot = 0; slot < GROUP_LEDGER_CAPACITY && free_slot == nullptr; slot++) {
            if (!ledger[slot].used) {
                free_slot = &ledger[slot];
            }
        }
    }
    if (free_slot == nullptr) {
        return false;
    }
    *free_slot = (struct ledger_entry){.used = true, .process = view->process, .start = view->start,
                                       .group = group, .session = session};
    return true;
}

/* The virtual ids of a process, found by walking up its ancestors until one has a record. A parent that started
 * after its child is a number the kernel gave away since, not the parent, and ends the walk. A walk that runs out of
 * depth is "incomplete": the answer is not that no record exists, so the caller must not fall back to the real ids. */
static struct virtual_ids resolve_by_walking(pid_t process) {
    pid_t current = process;
    unsigned long long child_start = ULLONG_MAX;
    for (int depth = 0; depth < GROUP_ANCESTRY_DEPTH; depth++) {
        struct process_view view;
        if (current <= 1 || !table->read(current, &view) || view.start > child_start) {
            return (struct virtual_ids){.known = false, .incomplete = false, .group = 0, .session = 0};
        }
        const struct ledger_entry *entry = entry_of(&view);
        if (entry != nullptr) {
            return (struct virtual_ids){.known = true, .incomplete = false, .group = entry->group, .session = entry->session};
        }
        child_start = view.start;
        current = view.parent;
    }
    return (struct virtual_ids){.known = false, .incomplete = true, .group = 0, .session = 0};
}

/* ---------------------------------------------------------------------------------- a snapshot */

/* Every process once, so a scan reads each process once however deep the tree is. */
struct snapshot {
    size_t count;
    bool complete;
    struct process_view views[GROUP_SCAN_LIMIT];
};

static struct snapshot scan;

static const struct process_view *find_in_scan(pid_t process) {
    for (size_t index = 0; index < scan.count; index++) {
        if (scan.views[index].process == process) {
            return &scan.views[index];
        }
    }
    return nullptr;
}

static void take_scan(void) {
    static pid_t processes[GROUP_SCAN_LIMIT + 1];
    size_t listed = table->list(processes, GROUP_SCAN_LIMIT);
    scan.complete = listed <= GROUP_SCAN_LIMIT;
    scan.count = 0;
    for (size_t index = 0; index < listed && index < GROUP_SCAN_LIMIT; index++) {
        if (table->read(processes[index], &scan.views[scan.count])) {
            scan.count++;
        }
    }
}

/* The virtual ids of a process of the scan, found through the scan, with the same rules as the walk. */
static struct virtual_ids resolve_in_scan(const struct process_view *view) {
    const struct process_view *current = view;
    for (int depth = 0; depth < GROUP_ANCESTRY_DEPTH; depth++) {
        const struct ledger_entry *entry = entry_of(current);
        if (entry != nullptr) {
            return (struct virtual_ids){.known = true, .incomplete = false, .group = entry->group, .session = entry->session};
        }
        const struct process_view *parent = current->parent > 1 ? find_in_scan(current->parent) : nullptr;
        if (parent == nullptr || parent->start > current->start) {
            return (struct virtual_ids){.known = false, .incomplete = false, .group = 0, .session = 0};
        }
        current = parent;
    }
    return (struct virtual_ids){.known = false, .incomplete = true, .group = 0, .session = 0};
}

/* The group and session a process is in as the scan sees it: the virtual ones, else the real ones. False when the
 * lookup was incomplete, which a caller treats as "cannot tell". */
static bool ids_in_scan(const struct process_view *view, pid_t *group, pid_t *session) {
    struct virtual_ids virtual_ids = resolve_in_scan(view);
    *group = virtual_ids.known ? virtual_ids.group : view->group;
    *session = virtual_ids.known ? virtual_ids.session : view->session;
    return !virtual_ids.incomplete;
}

/* Whether any process of the scan is in the group, and in which session (when session_of is not null). A process
 * whose lookup was incomplete sets uncertain, and the caller then refuses rather than guess. */
static bool group_exists(pid_t group, pid_t *session_of, bool *uncertain) {
    for (size_t index = 0; index < scan.count; index++) {
        pid_t member_group;
        pid_t member_session;
        if (!ids_in_scan(&scan.views[index], &member_group, &member_session)) {
            *uncertain = true;
        }
        if (member_group == group) {
            if (session_of != nullptr) {
                *session_of = member_session;
            }
            return true;
        }
    }
    return false;
}

/* ---------------------------------------------------------------------------------- the answers */

static struct group_answer pass_on(void) {
    return (struct group_answer){.pass_on = true, .value = 0, .error = 0};
}

static struct group_answer failure(int error) {
    return (struct group_answer){.pass_on = false, .value = -1, .error = error};
}

static struct group_answer success(long value) {
    return (struct group_answer){.pass_on = false, .value = value, .error = 0};
}

/* The calling process: the thread group of the notifying thread. */
static pid_t caller_of(const struct seccomp_notif *request) {
    return table->thread_group((pid_t)request->pid);
}

static struct group_answer decide_setsid(const struct seccomp_notif *request) {
    pid_t caller = caller_of(request);
    struct process_view view;
    if (caller <= 0 || !table->read(caller, &view)) {
        return failure(EPERM);
    }
    struct virtual_ids ids = resolve_by_walking(caller);
    pid_t group = ids.known ? ids.group : view.group;
    if (group == caller) {
        return failure(EPERM);
    }
    take_scan();
    bool uncertain = ids.incomplete;
    if (!scan.complete || group_exists(caller, nullptr, &uncertain) || uncertain) {
        return failure(EPERM);
    }
    if (!record_ids(&view, caller, caller)) {
        return failure(ENOMEM);
    }
    return success(caller);
}

static struct group_answer decide_setpgid(const struct seccomp_notif *request) {
    int pid_argument = (int)request->data.args[0];
    int group_argument = (int)request->data.args[1];
    pid_t caller = caller_of(request);
    if (group_argument < 0) {
        return failure(EINVAL);
    }
    struct process_view view;
    struct process_view caller_view;
    if (pid_argument < 0 || caller <= 0 || !table->read(caller, &caller_view)) {
        return failure(ESRCH);
    }
    pid_t target = pid_argument == 0 ? caller : (pid_t)pid_argument;
    if (target != caller && table->thread_group(target) != target) {
        return failure(table->thread_group(target) == 0 ? ESRCH : EINVAL);
    }
    if (!table->read(target, &view) || (target != caller && view.parent != caller)) {
        return failure(ESRCH);
    }
    take_scan();
    if (!scan.complete) {
        return failure(EPERM);
    }
    pid_t target_group;
    pid_t target_session;
    pid_t caller_group;
    pid_t caller_session;
    bool certain = ids_in_scan(&view, &target_group, &target_session);
    certain = ids_in_scan(&caller_view, &caller_group, &caller_session) && certain;
    if (!certain) {
        return failure(EPERM);
    }
    if (target_session != caller_session || target_session == target) {
        return failure(EPERM);
    }
    pid_t wanted = group_argument == 0 ? target : group_argument;
    if (wanted != target) {
        pid_t session_of_group = 0;
        bool uncertain = false;
        if (!group_exists(wanted, &session_of_group, &uncertain) || uncertain || session_of_group != target_session) {
            return failure(EPERM);
        }
    }
    if (!record_ids(&view, wanted, target_session)) {
        return failure(ENOMEM);
    }
    return success(0);
}

/* getpgid, getsid and getpgrp: the virtual id of the process asked about, else the kernel's answer. */
static struct group_answer decide_query(const struct seccomp_notif *request, bool want_session) {
    int pid_argument = request->data.nr == __NR_getpgid || request->data.nr == __NR_getsid
                           ? (int)request->data.args[0]
                           : 0;
    if (pid_argument < 0) {
        return pass_on();
    }
    pid_t process = pid_argument == 0 ? caller_of(request) : table->thread_group((pid_t)pid_argument);
    if (process <= 0) {
        return pass_on();
    }
    struct virtual_ids ids = resolve_by_walking(process);
    if (ids.incomplete) {
        return failure(EPERM);
    }
    if (!ids.known) {
        return pass_on();
    }
    return success(want_session ? ids.session : ids.group);
}

/* kill with a pid of zero or below. */
static struct group_answer decide_kill(const struct seccomp_notif *request) {
    int pid_argument = (int)request->data.args[0];
    int signal_number = (int)request->data.args[1];
    if (pid_argument > 0 || pid_argument == -1) {
        return pass_on();
    }
    if (signal_number < 0 || signal_number > GROUP_SIGNAL_MAXIMUM) {
        return pass_on();
    }
    pid_t group;
    if (pid_argument == 0) {
        pid_t caller = caller_of(request);
        struct virtual_ids ids = caller > 0 ? resolve_by_walking(caller) : (struct virtual_ids){.known = false};
        if (ids.incomplete) {
            return failure(EPERM);
        }
        if (!ids.known) {
            return pass_on();
        }
        group = ids.group;
    } else {
        group = (pid_t)(-(long long)pid_argument);
    }
    take_scan();
    if (!scan.complete) {
        return failure(EPERM);
    }
    int delivered = 0;
    int first_error = 0;
    bool any_member = false;
    bool uncertain = false;
    for (size_t index = 0; index < scan.count; index++) {
        struct virtual_ids ids = resolve_in_scan(&scan.views[index]);
        uncertain = uncertain || ids.incomplete;
        if (!ids.known || ids.group != group) {
            continue;
        }
        any_member = true;
        int error = table->signal(&scan.views[index], signal_number);
        if (error == 0) {
            delivered++;
        } else if (first_error == 0) {
            first_error = error;
        }
    }
    if (!any_member) {
        return uncertain ? failure(EPERM) : pass_on();
    }
    return delivered > 0 ? success(0) : failure(first_error != 0 ? first_error : ESRCH);
}

bool is_group_call(const struct seccomp_data *data) {
    if (data->arch != REPORT_NATIVE_AUDIT_ARCH) {
        return false;
    }
#ifdef __X32_SYSCALL_BIT
    if (((unsigned int)data->nr & __X32_SYSCALL_BIT) != 0) {
        return false;
    }
#endif
    switch (data->nr) {
    case __NR_setsid:
    case __NR_setpgid:
    case __NR_getpgid:
    case __NR_getsid:
#ifdef __NR_getpgrp
    case __NR_getpgrp:
#endif
    case __NR_kill:
        return true;
    default:
        return false;
    }
}

struct group_answer decide_group_call(const struct seccomp_notif *request) {
    int number = request->data.nr;
    struct group_answer answer;
    if (number == __NR_setsid) {
        answer = decide_setsid(request);
    } else if (number == __NR_setpgid) {
        answer = decide_setpgid(request);
    } else if (number == __NR_getsid) {
        answer = decide_query(request, true);
    } else if (number == __NR_kill) {
        answer = decide_kill(request);
    } else {
        answer = decide_query(request, false);
    }
    return answer;
}

void answer_group_call(int notify_descriptor, const struct seccomp_notif *request,
                       struct seccomp_notif_resp *response) {
    memset(response, 0, sizeof(*response));
    response->id = request->id;
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &response->id) != 0) {
        return;
    }
    struct group_answer answer = decide_group_call(request);
    if (answer.pass_on) {
        response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    } else if (answer.error != 0) {
        response->error = -answer.error;
    } else {
        response->val = answer.value;
    }
    (void)send_notification_response(notify_descriptor, response);
}

/* ---------------------------------------------------------------------------------- /proc */

static constexpr size_t STAT_LENGTH = 1024;
static constexpr int STAT_START_TOKEN = 19;
static constexpr int DECIMAL = 10;

bool parse_process_stat(const char *line, pid_t process, struct process_view *view) {
    const char *close_paren = strrchr(line, ')');
    if (close_paren == nullptr) {
        return false;
    }
    const char *cursor = close_paren + 1;
    long long numbers[4] = {0, 0, 0, 0};
    unsigned long long start = 0;
    for (int token = 0; token <= STAT_START_TOKEN; token++) {
        while (*cursor == ' ') {
            cursor++;
        }
        char *end = nullptr;
        if (token >= 1 && token <= 3) {
            numbers[token] = strtoll(cursor, &end, DECIMAL);
        } else if (token == STAT_START_TOKEN) {
            start = strtoull(cursor, &end, DECIMAL);
        } else {
            end = (char *)cursor;
            while (*end != ' ' && *end != '\0') {
                end++;
            }
        }
        if (end == cursor) {
            return false;
        }
        cursor = end;
    }
    view->process = process;
    view->parent = (pid_t)numbers[1];
    view->group = (pid_t)numbers[2];
    view->session = (pid_t)numbers[3];
    view->start = start;
    return true;
}

static bool proc_read(pid_t process, struct process_view *view) {
    char path[48];
    char text[STAT_LENGTH];
    snprintf(path, sizeof(path), "/proc/%d/stat", process);
    return read_small_file(path, text, sizeof(text), nullptr) && parse_process_stat(text, process, view);
}

pid_t parse_thread_group(const char *status) {
    const char *field = strstr(status, "\nTgid:");
    if (field == nullptr) {
        return 0;
    }
    long value = strtol(field + sizeof("\nTgid:") - 1, nullptr, DECIMAL);
    return value > 0 && value <= INT_MAX ? (pid_t)value : 0;
}

static pid_t proc_thread_group(pid_t thread) {
    char path[48];
    char text[2048];
    snprintf(path, sizeof(path), "/proc/%d/status", thread);
    return read_small_file(path, text, sizeof(text), nullptr) ? parse_thread_group(text) : 0;
}

/* Lists the numeric names of /proc. A /proc that cannot be opened answers "more than fit", the answer a scan
 * treats as incomplete, so the call is refused and never guessed. */
static size_t proc_list(pid_t *processes, size_t capacity) {
    DIR *directory = opendir("/proc");
    size_t count = 0;
    struct dirent *entry = nullptr;
    while (directory != nullptr && (entry = readdir(directory)) != nullptr) {
        char *end = nullptr;
        long value = strtol(entry->d_name, &end, DECIMAL);
        if (end == entry->d_name || *end != '\0' || value <= 0 || value > INT_MAX) {
            continue;
        }
        if (count == capacity) {
            closedir(directory);
            return capacity + 1;
        }
        processes[count++] = (pid_t)value;
    }
    if (directory != nullptr) {
        closedir(directory);
    }
    return directory == nullptr ? capacity + 1 : count;
}

/* Opens the process descriptor first and reads the start time after it, so the descriptor is the one
 * for the process whose start time matched: a number given away in between shows another start time. */
static int proc_signal(const struct process_view *target, int number) {
    long descriptor = syscall(SYS_pidfd_open, target->process, 0);
    if (descriptor < 0) {
        return errno;
    }
    struct process_view again;
    int error = 0;
    if (!proc_read(target->process, &again) || again.start != target->start || again.parent != target->parent) {
        error = ESRCH;
    } else if (syscall(SYS_pidfd_send_signal, (int)descriptor, number, nullptr, 0) != 0) {
        error = errno;
    }
    close((int)descriptor);
    return error;
}

static const struct process_table PROC_TABLE = {
    .read = proc_read,
    .thread_group = proc_thread_group,
    .list = proc_list,
    .signal = proc_signal,
};

void groups_configure(bool enable, const struct process_table *source) {
    enabled = enable;
    table = source != nullptr ? source : &PROC_TABLE;
}

bool groups_enabled(void) {
    return enabled;
}

const struct process_table *groups_table_for_tests(void) {
    return &PROC_TABLE;
}

void groups_reset_for_tests(void) {
    memset(ledger, 0, sizeof(ledger));
    enabled = false;
    table = &PROC_TABLE;
}
