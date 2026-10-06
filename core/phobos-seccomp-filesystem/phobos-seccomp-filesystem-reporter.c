#define _GNU_SOURCE
#include "phobos-seccomp-filesystem-reporter.h"

#include "phobos-seccomp-filesystem-access.h"
#include "phobos-seccomp-filesystem-path.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Room for the enforcer's whole command line, which the kernel limits to a quarter of the stack
 * limit, and for as many arguments as its rule tables and a command could ever give it. A command
 * line larger than that is not read, and filesystem reporting is then off for the run. */
static constexpr size_t ARGUMENT_AREA = 2U << 20;
static constexpr size_t ARGUMENT_COUNT_MAXIMUM = 16384;

/* Room for a path under /proc/<pid>. */
static constexpr size_t PROC_PATH_LENGTH = 64;

/* Room for a refusal the policy module words. */
static constexpr size_t REFUSAL_LENGTH = 512;

/* The status line that counts a task's seccomp filters, the marker of the filesystem domain. */
static const char FILTER_COUNT_KEY[] = "\nSeccomp_filters:";
static constexpr int DECIMAL = 10;

/* One command line, kept for as long as the model built from it: the model points into it. The
 * first arming uses the first, a second arming (the filesystem enforcer after the network one) the
 * second, so neither is ever overwritten. */
struct argument_slot {
    char text[ARGUMENT_AREA];
    char *vector[ARGUMENT_COUNT_MAXIMUM + 1];
    int count;
};

static struct argument_slot slots[2];
static struct options scratch_options;
static struct policy_model filesystem_model;
static struct policy_model network_model;
static char status_text[PROC_STATUS_LENGTH];
static enum reporter_state state = REPORTER_UNARMED;
static char enforcer_path[PATH_MAX];
static bool enforcer_known = false;
static int model_version = 0;
static bool filesystem_reporting = false;
static bool network_reporting = false;
static int armed_filter_count = 0;
static socket_type_lookup socket_types = NULL;

void reporter_configure(const char *landlock_bin, int landlock_version) {
    enforcer_known = realpath(landlock_bin, enforcer_path) != NULL;
    model_version = landlock_version;
}

enum reporter_state reporter_current_state(void) {
    return state;
}

void reporter_use_socket_types(socket_type_lookup lookup) {
    socket_types = lookup;
}

bool reporter_handles(const struct seccomp_notif *request) {
    if (request->data.arch != REPORT_NATIVE_AUDIT_ARCH) {
        return false;
    }
    for (size_t slot = 0; slot < REPORT_TRAPPED_CALL_COUNT; slot++) {
        if (REPORT_TRAPPED_CALLS[slot] == request->data.nr) {
            return true;
        }
    }
    return false;
}

/* Lets the kernel run the trapped call unchanged. This is the only answer an observation trap ever
 * gets. A send that finds the task gone fails with ENOENT, which is nobody's concern. A send
 * interrupted by a signal while it waits for the filter's lock fails with EINTR and is sent again:
 * the notification has been received, so the kernel never offers it a second time, and the call
 * would otherwise wait until its task is signalled. */
static void answer_continue(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id) {
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->val = 0;
    response->error = 0;
    response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    while (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_SEND, response) != 0 && errno == EINTR) {
    }
}

/* How many seccomp filters a status says its task carries, or -1 when it does not say. */
static int filter_count_in(const char *status) {
    const char *field = strstr(status, FILTER_COUNT_KEY);
    if (field == NULL) {
        return -1;
    }
    const char *number = field + sizeof(FILTER_COUNT_KEY) - 1;
    char *end = NULL;
    long count = strtol(number, &end, DECIMAL);
    if (end == number || count < 0 || count > INT_MAX) {
        return -1;
    }
    return (int)count;
}

/* Reads the task's /proc/<pid>/status into the view, for the filter count and the credentials. */
static bool read_task_status(struct task_view *task) {
    char path[PROC_PATH_LENGTH];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)task->pid);
    if (!read_small_file(path, status_text, sizeof(status_text), NULL)
        || !notification_still_valid(task)) {
        return false;
    }
    task->status = status_text;
    return true;
}

/* Whether the task that called landlock_restrict_self runs the enforcer the layers named. */
static bool caller_is_enforcer(const struct task_view *task) {
    char link[PROC_PATH_LENGTH];
    char executable[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)task->pid);
    ssize_t length = readlink(link, executable, sizeof(executable) - 1);
    if (length <= 0) {
        return false;
    }
    executable[length] = '\0';
    return strcmp(executable, enforcer_path) == 0 && notification_still_valid(task);
}

/* Reads the enforcer's command line into a slot and splits it into its arguments. The caller is
 * blocked in its trapped call meanwhile, so this is the command line it parsed and enforces. */
static bool read_arguments(const struct task_view *task, struct argument_slot *slot) {
    char path[PROC_PATH_LENGTH];
    size_t length = 0;
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)task->pid);
    if (!read_small_file(path, slot->text, sizeof(slot->text), &length) || length == 0
        || slot->text[length - 1] != '\0' || !notification_still_valid(task)) {
        return false;
    }
    slot->count = 0;
    for (size_t offset = 0; offset < length; offset += strlen(slot->text + offset) + 1) {
        if ((size_t)slot->count == ARGUMENT_COUNT_MAXIMUM) {
            return false;
        }
        slot->vector[slot->count] = slot->text + offset;
        slot->count++;
    }
    slot->vector[slot->count] = NULL;
    return true;
}

/* Says once why filesystem reporting is off for the rest of the run, and turns it off for good. */
static void turn_filesystem_reporting_off(const char *reason) {
    state = REPORTER_FILESYSTEM_ARMED;
    filesystem_reporting = false;
    fprintf(stderr, "Phobos: filesystem denial reporting is off for this run, because %s.\n",
            reason);
}

/* Whether every rule of the model names a path that reaches the same object for the supervisor as
 * for the enforcer, which opened it as itself. */
static bool rules_read_alike(const struct policy_model *model) {
    for (size_t number = 0; number < model->options.path_rule_count; number++) {
        if (!reads_alike_for_every_process(model->options.rules[number].path)) {
            return false;
        }
    }
    return true;
}

/* Builds the filesystem model from the filesystem enforcer's command line and records the filter
 * count every task of its domain will carry one more of. Only an enforcer that marks its domain
 * arms anything, since without the marker no task could be told to be inside it. */
static void arm_filesystem(const struct task_view *task, struct argument_slot *slot) {
    char error[REFUSAL_LENGTH];
    if (!scratch_options.mark_reported_domain) {
        turn_filesystem_reporting_off("the filesystem enforcer was not asked to mark its domain");
        return;
    }
    if (!build_policy_model(slot->count, slot->vector, model_version, &filesystem_model, error,
                            sizeof(error))) {
        turn_filesystem_reporting_off("the enforcer's rules could not be read the way the "
                                      "enforcer reads them");
        return;
    }
    if (!rules_read_alike(&filesystem_model)) {
        turn_filesystem_reporting_off("a rule names a path through /proc/self or "
                                      "/proc/thread-self, which reads differently for the "
                                      "reporter");
        return;
    }
    armed_filter_count = filter_count_in(task->status);
    if (armed_filter_count < 0) {
        turn_filesystem_reporting_off("the enforcer's seccomp filters could not be counted");
        return;
    }
    state = REPORTER_FILESYSTEM_ARMED;
    filesystem_reporting = true;
}

/* Arms on one landlock_restrict_self. Only the enforcer the layers named arms anything; once the
 * filesystem model is armed nothing re-arms, so the command cannot replace the model by running a
 * copy of the enforcer, which it can only reach after the filesystem enforcer armed it. */
static void arm(struct task_view *task) {
    if (state == REPORTER_FILESYSTEM_ARMED || !enforcer_known || !caller_is_enforcer(task)) {
        return;
    }
    struct argument_slot *slot = &slots[state == REPORTER_UNARMED ? 0 : 1];
    char error[REFUSAL_LENGTH];
    if (!read_arguments(task, slot) || !read_task_status(task)) {
        turn_filesystem_reporting_off("the enforcer's command line could not be read");
        return;
    }
    if (!parse_arguments_checked(slot->count, slot->vector, &scratch_options, error,
                                 sizeof(error))) {
        turn_filesystem_reporting_off("the enforcer's command line could not be read the way "
                                      "the enforcer reads it");
        return;
    }
    if (!scratch_options.no_filesystem) {
        arm_filesystem(task, slot);
    } else if (state == REPORTER_UNARMED) {
        network_reporting = build_policy_model(slot->count, slot->vector, model_version,
                                               &network_model, error, sizeof(error));
        state = REPORTER_NETWORK_ARMED;
    }
}

/* Judges one observed call: a bind by its port against the network model, when the guard's socket
 * table can name its transport, and any call of a task inside the filesystem domain against the
 * filesystem model. */
static void observe(struct task_view *task, const struct access_request *request) {
    if (request->kind == ACCESS_BIND && network_reporting) {
        judge_bind_port(task, request, &network_model, socket_types);
    }
    if (filesystem_reporting && read_task_status(task)
        && filter_count_in(task->status) > armed_filter_count) {
        judge_and_report(task, request, &filesystem_model);
    }
}

void reporter_service(int notify_descriptor, const struct seccomp_notif *request,
                      struct seccomp_notif_resp *response) {
    struct access_request decoded;
    struct task_view task = {.pid = (pid_t)request->pid,
                             .notify_descriptor = notify_descriptor,
                             .id = request->id,
                             .status = ""};
    if (decode_trapped_call(&request->data, &decoded)) {
        if (decoded.kind == ACCESS_ARMING) {
            arm(&task);
        } else {
            observe(&task, &decoded);
        }
    }
    answer_continue(notify_descriptor, response, request->id);
}

#ifdef PHOBOS_REPORTER_UNIT_TEST
void reset_reporter_for_tests(void) {
    state = REPORTER_UNARMED;
    enforcer_known = false;
    filesystem_reporting = false;
    network_reporting = false;
    armed_filter_count = 0;
    socket_types = NULL;
    filesystem_model.rule_count = 0;
}

size_t reporter_filesystem_rule_count(void) {
    return filesystem_model.rule_count;
}
#endif
