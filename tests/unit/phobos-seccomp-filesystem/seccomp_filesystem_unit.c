/*
 * Unit tests for the denial reporter's sources under core/phobos-seccomp-filesystem.
 *
 * The modules are linked, built with PHOBOS_REPORTER_UNIT_TEST so each case can start from an
 * empty run. What a module prints goes to standard error, so a case captures that stream in a
 * temporary file and judges the text byte for byte: the fixed parts of a line are a contract a
 * log search depends on.
 *
 * The enforcer's diagnostics-free model (-policy.c, -path-rule.c, -model.c) is linked here too,
 * without the enforcer's -diagnostics.c, which is the link test that a supervisor can carry the
 * model beside a diagnostics module of its own.
 *
 * The judge is held to a real directory tree the suite builds under /tmp, so path resolution,
 * symbolic links and inodes are the kernel's own. What the supervisor reads about the command is
 * faked through the linker's --wrap: its memory (process_vm_readv), its /proc links (readlink),
 * the notification's liveness (ioctl), and the few answers a case has to force (faccessat,
 * statvfs, statx, geteuid and the small /proc files).
 *
 * Called with --quote VALUE, the program prints VALUE quoted and nothing else, so the runner can
 * hold the quoting to bash's own over a corpus of names.
 */
#define _GNU_SOURCE
/* The runner builds with this defined; the lint job compiles this file on its own, without it. */
#ifndef PHOBOS_REPORTER_UNIT_TEST
#define PHOBOS_REPORTER_UNIT_TEST
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>

/* The file holding main is included with main renamed, so its stages can be driven one by one;
 * the modules beside it are linked. */
#define main sut_main
#include "../../../core/phobos-seccomp-filesystem/phobos-seccomp-filesystem.c"
#undef main

#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>

#include "../../../core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.h"
#include "../../../core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.h"
#include "../../../core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-access.h"
#include "../../../core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-judge.h"
#include "../../../core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.h"
#include "../../../core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-path.h"
#include "../../../core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-reporter.h"

/* ------------------------------------------------------------- test driver */

static int passed = 0;
static int failed = 0;

static void check(const char *what, bool condition) {
    if (condition) {
        printf("  ok    %s\n", what);
        passed++;
    } else {
        printf("  FAIL  %s\n", what);
        failed++;
    }
}

/* Room for everything one case writes to standard error. */
static constexpr size_t CAPTURED_LENGTH = 1 << 20;

static FILE *captured_file;
static int saved_stderr = -1;
static char captured_text[CAPTURED_LENGTH];

/* Points standard error at an empty temporary file until capture_stderr_end. */
static void capture_stderr_begin(void) {
    fflush(stderr);
    captured_file = tmpfile();
    saved_stderr = dup(STDERR_FILENO);
    if (captured_file == NULL || saved_stderr < 0
        || dup2(fileno(captured_file), STDERR_FILENO) < 0) {
        perror("capture");
        exit(2);
    }
}

/* Restores standard error and answers what was written to it meanwhile. */
static const char *capture_stderr_end(void) {
    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    rewind(captured_file);
    size_t length = fread(captured_text, 1, sizeof(captured_text) - 1, captured_file);
    captured_text[length] = '\0';
    fclose(captured_file);
    return captured_text;
}

static size_t count_occurrences(const char *text, const char *fragment) {
    size_t count = 0;
    size_t length = strlen(fragment);
    for (const char *at = strstr(text, fragment); at != NULL; at = strstr(at + length, fragment)) {
        count++;
    }
    return count;
}

/* ---------------------------------------------------------- the message module */

static void quoted_is(const char *what, const char *value, const char *expected) {
    char out[REPORT_QUOTED_MAXIMUM];
    quote_like_bash(value, out, sizeof(out));
    if (strcmp(out, expected) != 0) {
        printf("        got [%s], expected [%s]\n", out, expected);
    }
    check(what, strcmp(out, expected) == 0);
}

/* The quoting is bash's own: the runner also compares it with bash over a corpus. */
static void test_quoting_matches_bash(void) {
    printf("\nA path is quoted the way bash quotes it\n");
    quoted_is("printable text in single quotes", "/etc/hostname", "'/etc/hostname'");
    quoted_is("a newline as an ANSI-C escape", "/tmp/odd\nname", "$'/tmp/odd\\nname'");
    quoted_is("a quote in printable text closed and reopened", "/tmp/it's", "'/tmp/it'\\''s'");
    quoted_is("a quote beside a control byte escaped", "/tmp/q'and\nnl", "$'/tmp/q\\'and\\nnl'");
    quoted_is("a backslash in printable text kept", "/tmp/back\\slash", "'/tmp/back\\slash'");
    quoted_is("a backslash beside a control byte escaped", "/b\\s\nx", "$'/b\\\\s\\nx'");
    quoted_is("an escape byte as \\E", "/tmp/\x1b[31m", "$'/tmp/\\E[31m'");
    quoted_is("bytes above 0x7f in octal", "/tmp/\xc3\xa9", "$'/tmp/\\303\\251'");
    quoted_is("DEL in octal", "/tmp/del\x7f", "$'/tmp/del\\177'");
    quoted_is("the other named escapes", "/\a\b\t\v\f\r", "$'/\\a\\b\\t\\v\\f\\r'");
    quoted_is("another control byte in octal", "/x\x01", "$'/x\\001'");
    quoted_is("the empty name", "", "''");
}

/* A path longer than the shown maximum is cut there and marked as cut, outside the quotes. */
static void test_a_long_path_is_cut(void) {
    printf("\nA long path is cut\n");
    static char long_path[REPORT_PATH_SHOWN_MAXIMUM + 2];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';
    char out[REPORT_QUOTED_MAXIMUM];
    quote_like_bash(long_path, out, sizeof(out));
    check("the cut path keeps exactly the shown maximum",
          strlen(out) == REPORT_PATH_SHOWN_MAXIMUM + strlen("''") + strlen(" (truncated)"));
    check("and ends with the mark", strcmp(out + strlen(out) - strlen("' (truncated)"),
                                           "' (truncated)") == 0);
    static char exact[REPORT_PATH_SHOWN_MAXIMUM + 1];
    memset(exact, 'b', sizeof(exact) - 1);
    exact[sizeof(exact) - 1] = '\0';
    quote_like_bash(exact, out, sizeof(out));
    check("a path of exactly the shown maximum is not cut", strstr(out, "(truncated)") == NULL);
    char small[8];
    quote_like_bash("/a/long/name", small, sizeof(small));
    check("a buffer too small for the quoted path still ends in a NUL",
          strlen(small) < sizeof(small));
    char tiny[2] = {'x', 'x'};
    quote_like_bash("/a", tiny, sizeof(tiny));
    check("a buffer with no room for the quotes is left empty", tiny[0] == '\0');
    char untouched = 'x';
    quote_like_bash("/a", &untouched, 0);
    check("a buffer of no bytes is not written", untouched == 'x');
}

static void test_a_line_is_byte_exact(void) {
    printf("\nA line is byte exact\n");
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/etc/shadow", true, NULL);
    check("a read of a file",
          strcmp(capture_stderr_end(), "Phobos Security Error: the program tried to illegally "
                                       "read the File '/etc/shadow' but was blocked by Phobos.\n")
              == 0);
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_TIMEOUT, "leave", "Session", "", false, NULL);
    check("an empty object prints no space",
          strcmp(capture_stderr_end(), "Phobos Security Error: the program tried to illegally "
                                       "leave the Session but was blocked by Phobos.\n")
              == 0);
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_NETWORK, "use", "Kernel Interface", "io_uring", false, NULL);
    check("an object that is not a path is printed as it is",
          strcmp(capture_stderr_end(), "Phobos Security Error: the program tried to illegally "
                                       "use the Kernel Interface io_uring but was blocked by "
                                       "Phobos.\n")
              == 0);
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/tmp/odd\nname", true, NULL);
    check("a path with a control byte is quoted in the line",
          strcmp(capture_stderr_end(), "Phobos Security Error: the program tried to illegally "
                                       "read the File $'/tmp/odd\\nname' but was blocked by "
                                       "Phobos.\n")
              == 0);
}

static void test_named_path_and_truncation(void) {
    printf("\nThe path the program named, and a cut path, in a line\n");
    static char long_path[2048];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/etc/locale.alias", true,
                   "/usr/share/locale/locale.alias");
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", long_path, true, NULL);
    const char *text = capture_stderr_end();
    check("the named path follows the judged one",
          strstr(text, "the File '/etc/locale.alias' (named as '/usr/share/locale/locale.alias') "
                       "but was blocked by Phobos.\n")
              != NULL);
    check("a cut path is marked before the suffix",
          strstr(text, "' (truncated) but was blocked by Phobos.\n") != NULL);
}

static void test_repeats_are_counted_not_printed(void) {
    printf("\nA repeated action is counted, not printed\n");
    reset_report_for_tests();
    capture_stderr_begin();
    for (int round = 0; round < 1000; round++) {
        report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/etc/shadow", true, NULL);
    }
    report_summary();
    const char *text = capture_stderr_end();
    check("one line for a thousand repeats", count_occurrences(text, "Phobos Security Error") == 1);
    check("the summary counts every one of them",
          strstr(text, "Phobos Security Summary: Phobos blocked 1000 actions of the program, 1000 "
                       "in the filesystem layer, 0 in the network layer and 0 in the timeout "
                       "layer; 1 was shown above, 999 repeats and 0 beyond the limit of 100 lines "
                       "were not. (PHB-EDENY)\n")
              != NULL);
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/a", true, NULL);
    report_blocked(REPORT_LAYER_FILESYSTEM, "write", "File", "/a", true, NULL);
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "Directory", "/a", true, NULL);
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/b", true, NULL);
    check("a different verb, noun or object is a different line",
          count_occurrences(capture_stderr_end(), "Phobos Security Error") == 4);
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "ab", true, NULL);
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "Filea", "b", true, NULL);
    check("the parts of a key are kept apart",
          count_occurrences(capture_stderr_end(), "Phobos Security Error") == 2);
}

static void test_summary_singulars_and_silence(void) {
    printf("\nThe summary\n");
    reset_report_for_tests();
    capture_stderr_begin();
    report_summary();
    check("nothing counted prints nothing", strcmp(capture_stderr_end(), "") == 0);
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_TIMEOUT, "leave", "Session", "", false, NULL);
    report_summary();
    check("a count of one takes the singular",
          strstr(capture_stderr_end(),
                 "Phobos Security Summary: Phobos blocked 1 action of the program, 0 in the "
                 "filesystem layer, 0 in the network layer and 1 in the timeout layer; 1 was "
                 "shown above, 0 repeats and 0 beyond the limit of 100 lines were not. "
                 "(PHB-EDENY)\n")
              != NULL);
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_NETWORK, "connect to", "Endpoint", "10.0.0.1:443 over TCP", false,
                   NULL);
    report_blocked(REPORT_LAYER_NETWORK, "connect to", "Endpoint", "10.0.0.1:443 over TCP", false,
                   NULL);
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/x", true, NULL);
    report_summary();
    check("one repeat is a repeat, and the layers are counted apart",
          strstr(capture_stderr_end(),
                 "Phobos blocked 3 actions of the program, 1 in the filesystem layer, 2 in the "
                 "network layer and 0 in the timeout layer; 2 were shown above, 1 repeat and 0 "
                 "beyond the limit of 100 lines were not. (PHB-EDENY)\n")
              != NULL);
}

static void test_the_cap_holds(void) {
    printf("\nAt most a hundred distinct lines\n");
    reset_report_for_tests();
    capture_stderr_begin();
    char path[64];
    for (int number = 0; number < 150; number++) {
        snprintf(path, sizeof(path), "/denied/%d", number);
        report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", path, true, NULL);
    }
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/denied/120", true, NULL);
    report_summary();
    const char *text = capture_stderr_end();
    check("a hundred lines are printed", count_occurrences(text, "Phobos Security Error") == 100);
    check("the hundred and first is the only one past the cap that says so",
          count_occurrences(text, "Phobos: further blocked actions are counted but not shown.\n")
              == 1);
    check("the overflow notice follows the hundredth line",
          strstr(text, "'/denied/99' but was blocked by Phobos.\nPhobos: further blocked "
                       "actions are counted but not shown.\n")
              != NULL);
    check("the summary counts every one",
          strstr(text, "Phobos blocked 151 actions of the program, 151 in the filesystem layer")
              != NULL);
    check("a repeat past the cap is a repeat, and the rest are beyond the limit",
          strstr(text, "100 were shown above, 1 repeat and 50 beyond the limit of 100 lines")
              != NULL);
}

/* Once the table of keys is full a new distinct action can no longer be recognised when it
 * repeats, so it is counted beyond the limit every time; the counts still add up. */
static void test_a_full_table_still_counts(void) {
    printf("\nA full table of keys\n");
    reset_report_for_tests();
    capture_stderr_begin();
    char path[64];
    for (size_t number = 0; number < REPORT_KEYS_MAXIMUM + 10; number++) {
        snprintf(path, sizeof(path), "/denied/%zu", number);
        report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", path, true, NULL);
    }
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/denied/4100", true, NULL);
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/denied/0", true, NULL);
    report_summary();
    const char *text = capture_stderr_end();
    check("still a hundred lines", count_occurrences(text, "Phobos Security Error") == 100);
    check("every action counted, an unrecorded repeat beyond the limit and a recorded one a repeat",
          strstr(text, "Phobos blocked 4108 actions of the program, 4108 in the filesystem layer, "
                       "0 in the network layer and 0 in the timeout layer; 100 were shown above, 1 "
                       "repeat and 4007 beyond the limit of 100 lines were not. (PHB-EDENY)\n")
              != NULL);
}

/* --------------------------------------- the model links without the diagnostics */

/* The mode the model case creates its directory with. */
static constexpr mode_t MODEL_DIRECTORY_MODE = 0700;

static void test_the_model_links_without_diagnostics(void) {
    printf("\nThe enforcer's model links without the enforcer's diagnostics\n");
    char root[] = "/tmp/phobos-reporter-model-XXXXXX";
    if (mkdtemp(root) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    char inside[sizeof(root) + 8];
    snprintf(inside, sizeof(inside), "%s/inside", root);
    if (mkdir(inside, MODEL_DIRECTORY_MODE) != 0) {
        perror("mkdir");
        exit(2);
    }
    static struct policy_model model;
    char error[256];
    char *arguments[] = {"enforcer", "--rights=r", root, "--", "/bin/true", NULL};
    check("a model is built", build_policy_model(5, arguments, 8, &model, error, sizeof(error)));
    check("and grants what the rule grants",
          (model_rights_along(&model, inside) & LANDLOCK_ACCESS_FILESYSTEM_READ_FILE) != 0);
    check("and nothing more",
          (model_rights_along(&model, inside) & LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE) == 0);
    rmdir(inside);
    rmdir(root);
}

/* ------------------------------------------------------ decoding a trapped call */

/* A notification's data for one native call with the given arguments. */
static struct seccomp_data native_call(int number, uint64_t first, uint64_t second, uint64_t third,
                                       uint64_t fourth, uint64_t fifth) {
    struct seccomp_data data;
    memset(&data, 0, sizeof(data));
    data.nr = number;
    data.arch = REPORT_NATIVE_AUDIT_ARCH;
    data.args[0] = first;
    data.args[1] = second;
    data.args[2] = third;
    data.args[3] = fourth;
    data.args[4] = fifth;
    return data;
}

/* The descriptors and addresses the decoding cases hand in. None is real. */
static constexpr uint64_t NAME_ADDRESS = 0x1000;
static constexpr uint64_t OTHER_NAME_ADDRESS = 0x2000;
static constexpr int DIRECTORY_DESCRIPTOR = 3;
static constexpr int OTHER_DIRECTORY_DESCRIPTOR = 4;
static constexpr uint64_t AT_FDCWD_ARGUMENT = (uint64_t)(int64_t)AT_FDCWD;
static constexpr unsigned int FILE_MODE = 0644;
static constexpr int64_t TRUNCATE_LENGTH = 7;
static constexpr uint32_t SOCKADDR_LENGTH = 110;
static constexpr uint64_t OPEN_HOW_SIZE = 24;

static bool decodes(struct seccomp_data data, struct access_request *request) {
    memset(request, 0xa5, sizeof(*request));
    return decode_trapped_call(&data, request);
}

static bool names(const struct access_request *request, size_t index, int directory,
                  uint64_t address) {
    return request->objects[index].directory == directory
           && request->objects[index].name_address == address;
}

static void test_decode_the_at_calls(void) {
    printf("\nThe *at calls decode into their objects and flags\n");
    struct access_request request;
    check("openat names its directory, its name and its flags",
          decodes(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_WRONLY | O_CREAT,
                              FILE_MODE, 0),
                  &request)
              && request.kind == ACCESS_OPEN && request.object_count == 1
              && names(&request, 0, AT_FDCWD, NAME_ADDRESS)
              && request.open_flags == (O_WRONLY | O_CREAT));
    check("openat2 names where its open_how lies, not flags of its own",
          decodes(native_call(__NR_openat2, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, OTHER_NAME_ADDRESS,
                              OPEN_HOW_SIZE, 0),
                  &request)
              && request.kind == ACCESS_OPEN_HOW && names(&request, 0, DIRECTORY_DESCRIPTOR,
                                                          NAME_ADDRESS)
              && request.open_how_address == OTHER_NAME_ADDRESS
              && request.open_how_size == OPEN_HOW_SIZE);
    check("execve names its file relative to the working directory",
          decodes(native_call(__NR_execve, NAME_ADDRESS, 0, 0, 0, 0), &request)
              && request.kind == ACCESS_EXECUTE && names(&request, 0, AT_FDCWD, NAME_ADDRESS)
              && request.execute_flags == 0);
    check("execveat names its directory and its flags",
          decodes(native_call(__NR_execveat, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, 0, 0,
                              AT_SYMLINK_NOFOLLOW),
                  &request)
              && request.kind == ACCESS_EXECUTE && names(&request, 0, DIRECTORY_DESCRIPTOR,
                                                         NAME_ADDRESS)
              && request.execute_flags == AT_SYMLINK_NOFOLLOW);
    check("mkdirat names its directory and name",
          decodes(native_call(__NR_mkdirat, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, FILE_MODE, 0, 0),
                  &request)
              && request.kind == ACCESS_MAKE_DIRECTORY
              && names(&request, 0, DIRECTORY_DESCRIPTOR, NAME_ADDRESS));
    check("mknodat names its mode",
          decodes(native_call(__NR_mknodat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, S_IFIFO | FILE_MODE,
                              0, 0),
                  &request)
              && request.kind == ACCESS_MAKE_NODE && request.mode == (S_IFIFO | FILE_MODE));
    check("unlinkat names its flags",
          decodes(native_call(__NR_unlinkat, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, AT_REMOVEDIR, 0,
                              0),
                  &request)
              && request.kind == ACCESS_REMOVE && request.unlink_flags == AT_REMOVEDIR);
    check("renameat2 has two objects and its flags",
          decodes(native_call(__NR_renameat2, DIRECTORY_DESCRIPTOR, NAME_ADDRESS,
                              OTHER_DIRECTORY_DESCRIPTOR, OTHER_NAME_ADDRESS, RENAME_NOREPLACE),
                  &request)
              && request.kind == ACCESS_RENAME && request.object_count == 2
              && names(&request, 0, DIRECTORY_DESCRIPTOR, NAME_ADDRESS)
              && names(&request, 1, OTHER_DIRECTORY_DESCRIPTOR, OTHER_NAME_ADDRESS)
              && request.rename_flags == RENAME_NOREPLACE);
    check("linkat has two objects and its flags",
          decodes(native_call(__NR_linkat, DIRECTORY_DESCRIPTOR, NAME_ADDRESS,
                              OTHER_DIRECTORY_DESCRIPTOR, OTHER_NAME_ADDRESS, AT_SYMLINK_FOLLOW),
                  &request)
              && request.kind == ACCESS_LINK && request.object_count == 2
              && names(&request, 1, OTHER_DIRECTORY_DESCRIPTOR, OTHER_NAME_ADDRESS)
              && request.link_flags == AT_SYMLINK_FOLLOW);
    check("symlinkat names only the link, not its target",
          decodes(native_call(__NR_symlinkat, OTHER_NAME_ADDRESS, DIRECTORY_DESCRIPTOR,
                              NAME_ADDRESS, 0, 0),
                  &request)
              && request.kind == ACCESS_MAKE_SYMBOLIC_LINK && request.object_count == 1
              && names(&request, 0, DIRECTORY_DESCRIPTOR, NAME_ADDRESS));
    check("truncate names its file and its length",
          decodes(native_call(__NR_truncate, NAME_ADDRESS, (uint64_t)TRUNCATE_LENGTH, 0, 0, 0),
                  &request)
              && request.kind == ACCESS_TRUNCATE && names(&request, 0, AT_FDCWD, NAME_ADDRESS)
              && request.truncate_length == TRUNCATE_LENGTH);
    check("bind names its socket and where its address lies",
          decodes(native_call(__NR_bind, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, SOCKADDR_LENGTH, 0,
                              0),
                  &request)
              && request.kind == ACCESS_BIND && request.socket_descriptor == DIRECTORY_DESCRIPTOR
              && request.objects[0].name_address == NAME_ADDRESS
              && request.socket_address_length == SOCKADDR_LENGTH);
    check("landlock_restrict_self arms",
          decodes(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0), &request)
              && request.kind == ACCESS_ARMING && request.object_count == 0);
#ifdef __NR_renameat
    check("renameat has two objects and no flags",
          decodes(native_call(__NR_renameat, DIRECTORY_DESCRIPTOR, NAME_ADDRESS,
                              OTHER_DIRECTORY_DESCRIPTOR, OTHER_NAME_ADDRESS, RENAME_EXCHANGE),
                  &request)
              && request.kind == ACCESS_RENAME && request.object_count == 2
              && request.rename_flags == 0);
#endif
}

#ifdef __NR_open
/* The legacy x86-64 calls name everything relative to the working directory. */
static void test_decode_the_legacy_calls(void) {
    printf("\nThe legacy calls decode like their *at forms\n");
    struct access_request request;
    check("open", decodes(native_call(__NR_open, NAME_ADDRESS, O_RDONLY, 0, 0, 0), &request)
                      && request.kind == ACCESS_OPEN && names(&request, 0, AT_FDCWD, NAME_ADDRESS)
                      && request.open_flags == O_RDONLY);
    check("creat opens for writing, creating and truncating",
          decodes(native_call(__NR_creat, NAME_ADDRESS, FILE_MODE, 0, 0, 0), &request)
              && request.kind == ACCESS_OPEN
              && request.open_flags == (O_WRONLY | O_CREAT | O_TRUNC));
    check("mkdir", decodes(native_call(__NR_mkdir, NAME_ADDRESS, FILE_MODE, 0, 0, 0), &request)
                       && request.kind == ACCESS_MAKE_DIRECTORY
                       && names(&request, 0, AT_FDCWD, NAME_ADDRESS));
    check("mknod", decodes(native_call(__NR_mknod, NAME_ADDRESS, S_IFSOCK, 0, 0, 0), &request)
                       && request.kind == ACCESS_MAKE_NODE && request.mode == S_IFSOCK);
    check("unlink removes a file",
          decodes(native_call(__NR_unlink, NAME_ADDRESS, 0, 0, 0, 0), &request)
              && request.kind == ACCESS_REMOVE && request.unlink_flags == 0);
    check("rmdir removes a directory",
          decodes(native_call(__NR_rmdir, NAME_ADDRESS, 0, 0, 0, 0), &request)
              && request.kind == ACCESS_REMOVE && request.unlink_flags == AT_REMOVEDIR);
    check("rename", decodes(native_call(__NR_rename, NAME_ADDRESS, OTHER_NAME_ADDRESS, 0, 0, 0),
                            &request)
                        && request.kind == ACCESS_RENAME && request.rename_flags == 0
                        && names(&request, 1, AT_FDCWD, OTHER_NAME_ADDRESS));
    check("link", decodes(native_call(__NR_link, NAME_ADDRESS, OTHER_NAME_ADDRESS, 0, 0, 0),
                          &request)
                      && request.kind == ACCESS_LINK && request.link_flags == 0
                      && names(&request, 0, AT_FDCWD, NAME_ADDRESS));
    check("symlink names only the link",
          decodes(native_call(__NR_symlink, OTHER_NAME_ADDRESS, NAME_ADDRESS, 0, 0, 0), &request)
              && request.kind == ACCESS_MAKE_SYMBOLIC_LINK
              && names(&request, 0, AT_FDCWD, NAME_ADDRESS));
}
#endif

static void test_decode_refuses_what_it_does_not_know(void) {
    printf("\nWhat the decoder does not decode\n");
    struct access_request request;
    check("a number that is not a path call", !decodes(native_call(__NR_getpid, 0, 0, 0, 0, 0),
                                                       &request));
    struct seccomp_data foreign = native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, 0, 0,
                                              0);
    foreign.arch = AUDIT_ARCH_I386;
    check("a path call's number through a foreign ABI", !decodes(foreign, &request));
}

/* The report set never names a call the connect guard enforces, nor a call a Phobos filter refuses
 * outright, so an observation trap can never stand where an enforcement or refusal trap must. */
static void test_report_set_is_disjoint(void) {
    printf("\nThe report set is disjoint from the guard's and the refusals\n");
    const int excluded[] = {__NR_socket,         __NR_connect,         __NR_listen,
                            __NR_sendto,         __NR_sendmsg,         __NR_sendmmsg,
                            __NR_io_uring_setup, __NR_io_uring_enter,  __NR_io_uring_register,
                            __NR_setsid,         __NR_setpgid};
    bool disjoint = true;
    bool decodable = true;
    for (size_t index = 0; index < REPORT_TRAPPED_CALL_COUNT; index++) {
        for (size_t other = 0; other < sizeof(excluded) / sizeof(excluded[0]); other++) {
            disjoint = disjoint && REPORT_TRAPPED_CALLS[index] != excluded[other];
        }
        struct access_request request;
        decodable = decodable
                    && decodes(native_call(REPORT_TRAPPED_CALLS[index], 0, 0, 0, 0, 0), &request);
    }
    check("no trapped call is enforced by the guard or refused by a filter", disjoint);
    check("every trapped call is one the decoder decodes", decodable);
    check("the set holds the path calls, bind and the arming call",
          REPORT_TRAPPED_CALL_COUNT >= 14);
}

/* ------------------------------------------------------------------- the fakes */

/* The command every judged notification comes from, the listener and the notification. */
static constexpr pid_t FAKE_PID = 42;
static constexpr int FAKE_NOTIFY_DESCRIPTOR = 9;
static constexpr uint64_t FAKE_NOTIFICATION_ID = 555;

/* The command's memory, as pages of bytes. A read of an address on no page fails, as a read of
 * unmapped memory does. */
static constexpr size_t FAKE_PAGE_SIZE = 4096;
static constexpr size_t FAKE_PAGE_COUNT = 8;
struct fake_page {
    bool used;
    uint64_t address;
    unsigned char bytes[FAKE_PAGE_SIZE];
};
static struct fake_page fake_pages[FAKE_PAGE_COUNT];

static struct fake_page *fake_page_for(uint64_t address, bool create) {
    uint64_t base = address - address % FAKE_PAGE_SIZE;
    for (size_t slot = 0; slot < FAKE_PAGE_COUNT; slot++) {
        if (fake_pages[slot].used && fake_pages[slot].address == base) {
            return &fake_pages[slot];
        }
    }
    for (size_t slot = 0; create && slot < FAKE_PAGE_COUNT; slot++) {
        if (!fake_pages[slot].used) {
            fake_pages[slot].used = true;
            fake_pages[slot].address = base;
            memset(fake_pages[slot].bytes, 0, FAKE_PAGE_SIZE);
            return &fake_pages[slot];
        }
    }
    return NULL;
}

/* Places bytes in the command's memory at address, mapping the pages they need. */
static void fake_memory(uint64_t address, const void *bytes, size_t length) {
    for (size_t offset = 0; offset < length; offset++) {
        struct fake_page *page = fake_page_for(address + offset, true);
        page->bytes[(address + offset) % FAKE_PAGE_SIZE] = ((const unsigned char *)bytes)[offset];
    }
}

/* Places a NUL-terminated string in the command's memory. */
static void fake_string(uint64_t address, const char *text) {
    fake_memory(address, text, strlen(text) + 1);
}

ssize_t __wrap_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long local_count,
                                const struct iovec *remote, unsigned long remote_count,
                                unsigned long flags) {
    (void)local_count;
    (void)remote_count;
    (void)flags;
    if (pid != FAKE_PID) {
        errno = ESRCH;
        return -1;
    }
    uint64_t address = (uint64_t)(uintptr_t)remote->iov_base;
    size_t copied = 0;
    while (copied < remote->iov_len && copied < local->iov_len) {
        struct fake_page *page = fake_page_for(address + copied, false);
        if (page == NULL) {
            break;
        }
        ((unsigned char *)local->iov_base)[copied] = page->bytes[(address + copied) % FAKE_PAGE_SIZE];
        copied++;
    }
    if (copied == 0) {
        errno = EFAULT;
        return -1;
    }
    return (ssize_t)copied;
}

/* The command's /proc links, and any other link a case fakes. A link under /proc/42 that is not
 * here does not exist; a faked link with an empty target cannot be read. */
static constexpr size_t FAKE_LINK_COUNT = 16;
struct fake_link {
    char path[PATH_MAX];
    char target[PATH_MAX];
};
static struct fake_link fake_links[FAKE_LINK_COUNT];
static size_t fake_link_count = 0;

static void fake_readlink(const char *path, const char *target) {
    for (size_t index = 0; index < fake_link_count; index++) {
        if (strcmp(fake_links[index].path, path) == 0) {
            snprintf(fake_links[index].target, sizeof(fake_links[index].target), "%s", target);
            return;
        }
    }
    snprintf(fake_links[fake_link_count].path, sizeof(fake_links[0].path), "%s", path);
    snprintf(fake_links[fake_link_count].target, sizeof(fake_links[0].target), "%s", target);
    fake_link_count++;
}

ssize_t __real_readlink(const char *path, char *buffer, size_t size);
ssize_t __wrap_readlink(const char *path, char *buffer, size_t size) {
    for (size_t index = 0; index < fake_link_count; index++) {
        if (strcmp(fake_links[index].path, path) == 0) {
            size_t length = strlen(fake_links[index].target);
            length = length < size ? length : size;
            memcpy(buffer, fake_links[index].target, length);
            return (ssize_t)length;
        }
    }
    if (strncmp(path, "/proc/42/", strlen("/proc/42/")) == 0) {
        errno = ENOENT;
        return -1;
    }
    return __real_readlink(path, buffer, size);
}

/* Whether the notification is still pending. */
static bool fake_notification_valid = true;

/* ----------------------------------------------------------- the process fakes */

/* Everything the supervisor's process-level calls are scripted with, and everything they recorded.
 * It lives in shared memory because a case that ends in exit runs in a forked child of the suite
 * while the parent judges it. While script is NULL, or not active, every wrapped call is real. */
static constexpr size_t SCRIPT_LENGTH = 8;
static constexpr size_t CAPTURED_FILTER_MAXIMUM = 160;
static constexpr int FAKE_SOCKET_FIRST_END = 900;
static constexpr int FAKE_SOCKET_SECOND_END = 901;
static constexpr int FAKE_LISTENER = 902;
static constexpr int FAKE_CHILD_DESCRIPTOR = 903;
static constexpr pid_t FAKE_CHILD_PID = 4242;
static constexpr int EXEC_STAND_IN_STATUS = 200;

struct poll_step {
    int result;
    int error;
    short listener_events;
    short child_events;
};

struct process_script {
    bool active;
    pid_t forks[SCRIPT_LENGTH];
    size_t fork_count;
    size_t fork_next;
    bool socketpair_fails;
    bool prctl_fails;
    long listener_result;
    int listener_error;
    bool notif_sizes_fail;
    bool notif_sizes_small;
    long pidfd_result;
    long setpgid_result;
    int setpgid_error;
    int receive_result;
    bool send_result;
    bool set_flags_fails;
    bool send_fails;
    unsigned int sends_interrupted;
    bool calloc_fails;
    struct poll_step polls[SCRIPT_LENGTH];
    size_t poll_count;
    size_t poll_next;
    struct seccomp_data notifications[SCRIPT_LENGTH];
    size_t notification_count;
    size_t notification_next;
    ssize_t read_result;
    pid_t read_value;
    ssize_t write_result;
    int wait_status;
    bool wait_fails;
    int reaped_status;
    bool reap_faked;
    bool reap_unread;
    unsigned int child_signal_taken;
    unsigned int child_signal_restored;
    int fake_landlock_version;
    bool landlock_version_faked;
    int fake_continue;
    int fake_group_lock;
    unsigned int responses_sent;
    struct seccomp_notif_resp last_response;
    bool every_response_continued;
    unsigned int filters_installed;
    unsigned int installed_flags;
    unsigned short installed_length;
    struct sock_filter installed[CAPTURED_FILTER_MAXIMUM];
    char executed[PATH_MAX];
    unsigned int executions;
    unsigned int drainers_started;
};

static struct process_script *script = NULL;

/* How a child of the suite ends when the code under test returned instead of exiting, how the
 * continue probe ends when it fails (PROBE_FAILED in -handoff.c), and how a command the fake execvp
 * stands in for ends. */
static constexpr int RETURNED_STATUS = 99;
static constexpr int PROBE_FAILED_STATUS = 3;
static constexpr int SIGNATURE_SEEN_STATUS = 42;
static constexpr int EXIT_CODE_STAND_IN = EXEC_STAND_IN_STATUS;

static bool scripted(void) {
    return script != NULL && script->active;
}

/* A fresh script: one supervisor that forks a child, whose listener arrives and is answered. */
static void reset_script(void) {
    memset(script, 0, sizeof(*script));
    script->active = true;
    script->listener_result = FAKE_LISTENER;
    script->receive_result = FAKE_LISTENER;
    script->send_result = true;
    script->pidfd_result = FAKE_CHILD_DESCRIPTOR;
    script->setpgid_result = -1;
    script->setpgid_error = EINVAL;
    script->read_result = sizeof(pid_t);
    script->write_result = sizeof(pid_t);
    script->every_response_continued = true;
    script->fake_continue = -1;
    script->fake_group_lock = -1;
}

static void script_forks(pid_t first, pid_t second, pid_t third) {
    script->forks[0] = first;
    script->forks[1] = second;
    script->forks[2] = third;
    script->fork_count = 3;
}

static void script_poll(int result, short listener_events, short child_events) {
    struct poll_step *step = &script->polls[script->poll_count++];
    step->result = result;
    step->error = result < 0 ? EBADF : 0;
    step->listener_events = listener_events;
    step->child_events = child_events;
}

static void script_notification(struct seccomp_data data) {
    script->notifications[script->notification_count++] = data;
}

extern void __gcov_dump(void) __attribute__((weak));
void __real__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status) {
    if (__gcov_dump != NULL) {
        __gcov_dump();
    }
    __real__exit(status);
}

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size) {
    if (scripted() && script->calloc_fails) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(count, size);
}

pid_t __real_fork(void);
pid_t __wrap_fork(void) {
    if (!scripted() || script->fork_next >= script->fork_count) {
        return __real_fork();
    }
    pid_t result = script->forks[script->fork_next++];
    if (result < 0) {
        errno = EAGAIN;
    }
    return result;
}

int __real_socketpair(int domain, int type, int protocol, int pair[2]);
int __wrap_socketpair(int domain, int type, int protocol, int pair[2]) {
    if (!scripted()) {
        return __real_socketpair(domain, type, protocol, pair);
    }
    if (script->socketpair_fails) {
        errno = EMFILE;
        return -1;
    }
    pair[0] = FAKE_SOCKET_FIRST_END;
    pair[1] = FAKE_SOCKET_SECOND_END;
    return 0;
}

int __real_prctl(int option, unsigned long second, unsigned long third, unsigned long fourth,
                 unsigned long fifth);
int __wrap_prctl(int option, unsigned long second, unsigned long third, unsigned long fourth,
                 unsigned long fifth) {
    if (!scripted()) {
        return __real_prctl(option, second, third, fourth, fifth);
    }
    if (script->prctl_fails) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...) {
    va_list arguments;
    va_start(arguments, number);
    unsigned long first = va_arg(arguments, unsigned long);
    unsigned long second = va_arg(arguments, unsigned long);
    unsigned long third = va_arg(arguments, unsigned long);
    va_end(arguments);
    if (!scripted()) {
        return __real_syscall(number, first, second, third);
    }
    if (number == SYS_seccomp && first == SECCOMP_SET_MODE_FILTER) {
        const struct sock_fprog *program = (const struct sock_fprog *)(uintptr_t)third;
        script->filters_installed++;
        script->installed_flags = (unsigned int)second;
        script->installed_length = program->len;
        memcpy(script->installed, program->filter,
               program->len * sizeof(struct sock_filter) <= sizeof(script->installed)
                   ? program->len * sizeof(struct sock_filter)
                   : sizeof(script->installed));
        errno = script->listener_error;
        return script->listener_result;
    }
    if (number == SYS_seccomp && first == SECCOMP_GET_NOTIF_SIZES) {
        struct seccomp_notif_sizes *sizes = (struct seccomp_notif_sizes *)(uintptr_t)third;
        if (script->notif_sizes_fail) {
            errno = EINVAL;
            return -1;
        }
        sizes->seccomp_notif = script->notif_sizes_small ? 1 : sizeof(struct seccomp_notif) + 16;
        sizes->seccomp_notif_resp =
            script->notif_sizes_small ? 1 : sizeof(struct seccomp_notif_resp) + 16;
        return 0;
    }
    if (number == SYS_pidfd_open) {
        errno = ENOSYS;
        return script->pidfd_result;
    }
    if (number == SYS_setpgid) {
        errno = script->setpgid_error;
        return script->setpgid_result;
    }
    return __real_syscall(number, first, second, third);
}

bool __real_send_descriptor(int socket_descriptor, int descriptor_to_send);
bool __wrap_send_descriptor(int socket_descriptor, int descriptor_to_send) {
    if (!scripted()) {
        return __real_send_descriptor(socket_descriptor, descriptor_to_send);
    }
    errno = script->send_result ? 0 : EPIPE;
    return script->send_result;
}

int __real_receive_descriptor(int socket_descriptor);
int __wrap_receive_descriptor(int socket_descriptor) {
    return scripted() ? script->receive_result : __real_receive_descriptor(socket_descriptor);
}

int __real_poll(struct pollfd *watch, nfds_t count, int timeout);
int __wrap_poll(struct pollfd *watch, nfds_t count, int timeout) {
    if (!scripted()) {
        return __real_poll(watch, count, timeout);
    }
    if (script->poll_next >= script->poll_count) {
        errno = EBADF;
        return -1;
    }
    struct poll_step *step = &script->polls[script->poll_next++];
    watch[0].revents = step->listener_events;
    if (count > 1) {
        watch[1].revents = step->child_events;
    }
    errno = step->error;
    return step->result;
}

ssize_t __real_read(int descriptor, void *buffer, size_t size);
ssize_t __wrap_read(int descriptor, void *buffer, size_t size) {
    if (!scripted() || descriptor != FAKE_SOCKET_FIRST_END) {
        return __real_read(descriptor, buffer, size);
    }
    if (script->read_result == (ssize_t)sizeof(pid_t)) {
        memcpy(buffer, &script->read_value, sizeof(pid_t));
    }
    return script->read_result;
}

ssize_t __real_write(int descriptor, const void *buffer, size_t size);
ssize_t __wrap_write(int descriptor, const void *buffer, size_t size) {
    if (!scripted() || descriptor != FAKE_SOCKET_SECOND_END) {
        return __real_write(descriptor, buffer, size);
    }
    return script->write_result;
}

pid_t __real_waitpid(pid_t pid, int *status, int options);
pid_t __wrap_waitpid(pid_t pid, int *status, int options) {
    if (!scripted() || pid != FAKE_CHILD_PID) {
        return __real_waitpid(pid, status, options);
    }
    if (script->wait_fails) {
        errno = ECHILD;
        return -1;
    }
    *status = script->wait_status;
    return pid;
}

/* Records each change of SIGCHLD's disposition while a case is scripted, then makes it: giving it
 * the default while keeping the old one is the supervisor taking it over, and setting one without
 * keeping is giving it back. */
int __real_sigaction(int signum, const struct sigaction *action, struct sigaction *old);
int __wrap_sigaction(int signum, const struct sigaction *action, struct sigaction *old) {
    if (scripted() && signum == SIGCHLD && action != NULL && old != NULL
        && action->sa_handler == SIG_DFL) {
        script->child_signal_taken++;
    } else if (scripted() && signum == SIGCHLD && action != NULL && old == NULL) {
        script->child_signal_restored++;
    }
    return __real_sigaction(signum, action, old);
}

bool __real_reap_command(pid_t child, const sigset_t *forwarded, int *status);
bool __wrap_reap_command(pid_t child, const sigset_t *forwarded, int *status) {
    if (!scripted() || !script->reap_faked) {
        return __real_reap_command(child, forwarded, status);
    }
    *status = script->reaped_status;
    return !script->reap_unread;
}

int __real_execvp(const char *file, char *const arguments[]);
int __wrap_execvp(const char *file, char *const arguments[]) {
    if (!scripted()) {
        return __real_execvp(file, arguments);
    }
    snprintf(script->executed, sizeof(script->executed), "%s", file);
    script->executions++;
    if (strcmp(file, "/no/such/program") == 0) {
        errno = ENOENT;
        return -1;
    }
    _exit(EXEC_STAND_IN_STATUS);
}

int __real_query_landlock_version(void);
int __wrap_query_landlock_version(void) {
    return scripted() && script->landlock_version_faked ? script->fake_landlock_version
                                                       : __real_query_landlock_version();
}

bool __real_continue_supported(void);
bool __wrap_continue_supported(void) {
    return scripted() && script->fake_continue >= 0 ? script->fake_continue == 1
                                                    : __real_continue_supported();
}

bool __real_group_lock_present(void);
bool __wrap_group_lock_present(void) {
    return scripted() && script->fake_group_lock >= 0 ? script->fake_group_lock == 1
                                                      : __real_group_lock_present();
}

/* Records every answer sent on the listener, and plays the notifications and flags a script holds. */
int __real_ioctl(int descriptor, unsigned long request, ...);
int __wrap_ioctl(int descriptor, unsigned long request, ...) {
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    if (request == SECCOMP_IOCTL_NOTIF_ID_VALID) {
        if (fake_notification_valid) {
            return 0;
        }
        errno = ENOENT;
        return -1;
    }
    if (request == SECCOMP_IOCTL_NOTIF_SEND && script != NULL) {
        memcpy(&script->last_response, argument, sizeof(script->last_response));
        script->responses_sent++;
        script->every_response_continued =
            script->every_response_continued
            && script->last_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE
            && script->last_response.error == 0 && script->last_response.val == 0;
        if (script->sends_interrupted > 0) {
            script->sends_interrupted--;
            errno = EINTR;
            return -1;
        }
        if (scripted() && script->send_fails) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    if (request == SECCOMP_IOCTL_NOTIF_RECV && scripted()) {
        if (script->notification_next >= script->notification_count) {
            errno = ENOENT;
            return -1;
        }
        struct seccomp_notif *notification = argument;
        notification->id = FAKE_NOTIFICATION_ID + script->notification_next;
        notification->pid = FAKE_PID;
        notification->data = script->notifications[script->notification_next++];
        return 0;
    }
    if (request == SECCOMP_IOCTL_NOTIF_SET_FLAGS && scripted()) {
        if (script->set_flags_fails) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    return __real_ioctl(descriptor, request, argument);
}

/* A path the file mode refuses the access bits in fake_refused_mode on, a mount that is
 * read-only, noexec or nodev, a mount that differs, a file that is append-only, a statx that fails.
 * Empty means none. */
static char fake_refused_access[PATH_MAX];
static int fake_refused_mode = R_OK | W_OK | X_OK;
static char fake_read_only_mount[PATH_MAX];
static char fake_noexec_mount[PATH_MAX];
static char fake_nodev_mount[PATH_MAX];
static char fake_other_mount[PATH_MAX];
static char fake_append_only[PATH_MAX];
static bool fake_statx_fails = false;

static bool beneath_or_at(const char *path, const char *prefix) {
    size_t length = strlen(prefix);
    return length > 0 && strncmp(path, prefix, length) == 0
           && (path[length] == '\0' || path[length] == '/');
}

int __real_faccessat(int directory, const char *path, int mode, int flags);
int __wrap_faccessat(int directory, const char *path, int mode, int flags) {
    if (fake_refused_access[0] != '\0' && strcmp(path, fake_refused_access) == 0
        && (mode & fake_refused_mode) != 0) {
        errno = EACCES;
        return -1;
    }
    return __real_faccessat(directory, path, mode, flags);
}

int __real_statvfs(const char *path, struct statvfs *status);
int __wrap_statvfs(const char *path, struct statvfs *status) {
    int result = __real_statvfs(path, status);
    if (result == 0 && beneath_or_at(path, fake_read_only_mount)) {
        status->f_flag |= ST_RDONLY;
    }
    if (result == 0 && beneath_or_at(path, fake_noexec_mount)) {
        status->f_flag |= ST_NOEXEC;
    }
    if (result == 0 && beneath_or_at(path, fake_nodev_mount)) {
        status->f_flag |= ST_NODEV;
    }
    return result;
}

int __real_statx(int directory, const char *path, int flags, unsigned int mask, struct statx *status);
int __wrap_statx(int directory, const char *path, int flags, unsigned int mask,
                 struct statx *status) {
    if (fake_statx_fails) {
        errno = ENOSYS;
        return -1;
    }
    int result = __real_statx(directory, path, flags, mask, status);
    if (result == 0 && beneath_or_at(path, fake_other_mount)) {
        status->stx_mnt_id += 1000;
    }
    if (result == 0 && fake_append_only[0] != '\0' && strcmp(path, fake_append_only) == 0) {
        status->stx_attributes |= STATX_ATTR_APPEND;
    }
    return result;
}

/* The supervisor's own status and the command's UNIX socket table, when a case fakes them, and
 * further small files by path. A faked file whose bytes are NULL cannot be read. A file under
 * /proc/<pid> of a fake process that is not faked cannot be read either. */
static const char *fake_own_status = NULL;
static const char *fake_unix_table = NULL;
static constexpr size_t FAKE_FILE_COUNT = 8;
struct fake_file {
    char path[64];
    const char *bytes;
    size_t length;
};
static struct fake_file fake_files[FAKE_FILE_COUNT];
static size_t fake_file_count = 0;

static void fake_small_file(const char *path, const char *bytes, size_t length) {
    for (size_t slot = 0; slot < fake_file_count; slot++) {
        if (strcmp(fake_files[slot].path, path) == 0) {
            fake_files[slot].bytes = bytes;
            fake_files[slot].length = length;
            return;
        }
    }
    snprintf(fake_files[fake_file_count].path, sizeof(fake_files[0].path), "%s", path);
    fake_files[fake_file_count].bytes = bytes;
    fake_files[fake_file_count].length = length;
    fake_file_count++;
}

/* The faked contents of a path, and whether the path is faked at all. */
static bool faked_file(const char *path, const char **bytes, size_t *length) {
    if (strcmp(path, "/proc/self/status") == 0 && fake_own_status != NULL) {
        *bytes = fake_own_status;
        *length = strlen(fake_own_status);
        return true;
    }
    if (strcmp(path, "/proc/42/net/unix") == 0) {
        *bytes = fake_unix_table;
        *length = fake_unix_table == NULL ? 0 : strlen(fake_unix_table);
        return true;
    }
    for (size_t slot = 0; slot < fake_file_count; slot++) {
        if (strcmp(fake_files[slot].path, path) == 0) {
            *bytes = fake_files[slot].bytes;
            *length = fake_files[slot].length;
            return true;
        }
    }
    *bytes = NULL;
    *length = 0;
    return strncmp(path, "/proc/42/", strlen("/proc/42/")) == 0;
}

bool __real_read_small_file(const char *path, char *out, size_t size, size_t *length);
bool __wrap_read_small_file(const char *path, char *out, size_t size, size_t *length) {
    const char *bytes = NULL;
    size_t bytes_length = 0;
    if (!faked_file(path, &bytes, &bytes_length)) {
        return __real_read_small_file(path, out, size, length);
    }
    if (bytes == NULL || bytes_length >= size) {
        return false;
    }
    memcpy(out, bytes, bytes_length);
    out[bytes_length] = '\0';
    if (length != NULL) {
        *length = bytes_length;
    }
    return true;
}

/* The supervisor's effective user, when a case fakes it. */
static bool fake_euid_set = false;
static uid_t fake_euid = 0;

uid_t __real_geteuid(void);
uid_t __wrap_geteuid(void) {
    return fake_euid_set ? fake_euid : __real_geteuid();
}

/* Puts every fake back to its default: no memory, no links but the command's root, a live
 * notification, and every answer the kernel's own. */
static void reset_fakes(void) {
    memset(fake_pages, 0, sizeof(fake_pages));
    fake_link_count = 0;
    fake_readlink("/proc/42/root", "/");
    fake_notification_valid = true;
    fake_refused_access[0] = '\0';
    fake_refused_mode = R_OK | W_OK | X_OK;
    fake_read_only_mount[0] = '\0';
    fake_noexec_mount[0] = '\0';
    fake_nodev_mount[0] = '\0';
    fake_other_mount[0] = '\0';
    fake_append_only[0] = '\0';
    fake_statx_fails = false;
    fake_own_status = NULL;
    fake_unix_table = NULL;
    fake_euid_set = false;
    fake_file_count = 0;
    memset(script, 0, sizeof(*script));
    script->every_response_continued = true;
    reset_judge_for_tests();
}

/* ------------------------------------------------------------- reading the command */

static struct task_view fake_task(const char *status) {
    struct task_view task = {.pid = FAKE_PID,
                             .notify_descriptor = FAKE_NOTIFY_DESCRIPTOR,
                             .id = FAKE_NOTIFICATION_ID,
                             .status = status};
    return task;
}

static void test_reading_names(void) {
    printf("\nReading a name out of the command\n");
    reset_fakes();
    struct task_view task = fake_task("");
    char out[PATH_MAX];
    struct named_object absolute = {.directory = AT_FDCWD, .name_address = NAME_ADDRESS};
    fake_string(NAME_ADDRESS, "/etc/hostname");
    check("an absolute name is read as it is",
          read_absolute_name(&task, &absolute, out, sizeof(out))
              && strcmp(out, "/etc/hostname") == 0);
    fake_string(NAME_ADDRESS, "out/report.txt");
    fake_readlink("/proc/42/cwd", "/var/tmp/testing-dir");
    check("a relative name is made absolute against the working directory",
          read_absolute_name(&task, &absolute, out, sizeof(out))
              && strcmp(out, "/var/tmp/testing-dir/out/report.txt") == 0);
    fake_readlink("/proc/42/cwd", "/");
    check("against the root there is no double slash",
          read_absolute_name(&task, &absolute, out, sizeof(out))
              && strcmp(out, "/out/report.txt") == 0);
    struct named_object relative = {.directory = DIRECTORY_DESCRIPTOR, .name_address = NAME_ADDRESS};
    fake_readlink("/proc/42/fd/3", "/srv/data");
    check("a name relative to a descriptor is made absolute against it",
          read_absolute_name(&task, &relative, out, sizeof(out))
              && strcmp(out, "/srv/data/out/report.txt") == 0);
    fake_readlink("/proc/42/fd/3", "/srv/gone (deleted)");
    check("a directory that was removed is not judged",
          !read_absolute_name(&task, &relative, out, sizeof(out)));
    fake_readlink("/proc/42/fd/3", "(unreachable)/srv");
    check("a directory outside the root is not judged",
          !read_absolute_name(&task, &relative, out, sizeof(out)));
    fake_readlink("/proc/42/fd/3", "socket:[77]");
    check("a descriptor that is no directory is not judged",
          !read_absolute_name(&task, &relative, out, sizeof(out)));
    fake_readlink("/proc/42/fd/3", "/x");
    check("a directory named exactly like the deleted marker's length is judged",
          read_absolute_name(&task, &relative, out, sizeof(out))
              && strcmp(out, "/x/out/report.txt") == 0);
    struct named_object negative = {.directory = -5, .name_address = NAME_ADDRESS};
    check("a negative descriptor other than AT_FDCWD is not judged",
          !read_absolute_name(&task, &negative, out, sizeof(out)));
    struct named_object unknown = {.directory = OTHER_DIRECTORY_DESCRIPTOR,
                                   .name_address = NAME_ADDRESS};
    check("a descriptor whose link cannot be read is not judged",
          !read_absolute_name(&task, &unknown, out, sizeof(out)));
    char small[8];
    check("a joined name that does not fit is not judged",
          !read_absolute_name(&task, &relative, small, sizeof(small)));
    fake_string(NAME_ADDRESS, "/a/long/absolute/name");
    check("an absolute name that does not fit is not judged",
          !read_absolute_name(&task, &absolute, small, sizeof(small)));
    fake_string(NAME_ADDRESS, "");
    check("an empty name is not judged", !read_absolute_name(&task, &absolute, out, sizeof(out)));
    struct named_object unmapped = {.directory = AT_FDCWD, .name_address = 0x900000};
    check("a name in unmapped memory is not judged",
          !read_absolute_name(&task, &unmapped, out, sizeof(out)));
    static char endless[FAKE_PAGE_SIZE * 2];
    memset(endless, 'a', sizeof(endless));
    endless[0] = '/';
    fake_memory(NAME_ADDRESS, endless, sizeof(endless));
    check("a name with no end within PATH_MAX is not judged",
          !read_absolute_name(&task, &absolute, out, sizeof(out)));
    reset_fakes();
    static char across[FAKE_PAGE_SIZE];
    memset(across, 'b', sizeof(across));
    across[0] = '/';
    snprintf(across + FAKE_PAGE_SIZE - 40, 40, "/end");
    fake_memory(NAME_ADDRESS + FAKE_PAGE_SIZE / 2, across, strlen(across) + 1);
    struct named_object spanning = {.directory = AT_FDCWD,
                                    .name_address = NAME_ADDRESS + FAKE_PAGE_SIZE / 2};
    check("a name that crosses a page is read whole",
          read_absolute_name(&task, &spanning, out, sizeof(out)) && strlen(out) == strlen(across));
    fake_string(NAME_ADDRESS, "/etc/hostname");
    fake_notification_valid = false;
    check("a name read for a notification that vanished is not trusted",
          !read_absolute_name(&task, &absolute, out, sizeof(out)));
    struct task_view stranger = task;
    stranger.pid = FAKE_PID + 1;
    fake_notification_valid = true;
    check("bytes of another process are not read",
          !read_command_bytes(&stranger, NAME_ADDRESS, out, 4));
}

static void test_resolving_names(void) {
    printf("\nResolving a name the way Landlock sees it\n");
    static char own_status_text[PROC_STATUS_LENGTH];
    __real_read_small_file("/proc/self/status", own_status_text, sizeof(own_status_text), NULL);
    struct task_view task = fake_task(own_status_text);
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    check("an object resolves to itself",
          resolve_for_landlock(&task, "/proc/self/..", false, anchor, sizeof(anchor), shown,
                               sizeof(shown))
              && strcmp(anchor, "/proc") == 0 && strcmp(shown, "/proc") == 0);
    check("a name to create resolves its parent and keeps the last name",
          resolve_for_landlock(&task, "/proc/../tmp/new", true, anchor, sizeof(anchor), shown,
                               sizeof(shown))
              && strcmp(anchor, "/tmp") == 0 && strcmp(shown, "/tmp/new") == 0);
    check("a name directly in the root has the root as its parent",
          resolve_for_landlock(&task, "/new", true, anchor, sizeof(anchor), shown, sizeof(shown))
              && strcmp(anchor, "/") == 0 && strcmp(shown, "/new") == 0);
    check("a missing object does not resolve",
          !resolve_for_landlock(&task, "/no/such/thing", false, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    check("a missing parent does not resolve",
          !resolve_for_landlock(&task, "/no/such/thing", true, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    check("a dot entry is no name to create",
          !resolve_for_landlock(&task, "/tmp/..", true, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    check("nor is a single dot",
          !resolve_for_landlock(&task, "/tmp/.", true, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    check("nor an empty last name",
          !resolve_for_landlock(&task, "/tmp/", true, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    check("a relative name does not resolve",
          !resolve_for_landlock(&task, "tmp/x", true, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    static char overlong[PATH_MAX + 8];
    memset(overlong, 'c', sizeof(overlong) - 1);
    overlong[0] = '/';
    overlong[sizeof(overlong) - 1] = '\0';
    check("a name longer than PATH_MAX does not resolve",
          !resolve_for_landlock(&task, overlong, false, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    char small[4];
    check("a resolved path that does not fit is refused",
          !resolve_for_landlock(&task, "/proc", false, small, sizeof(small), shown,
                                sizeof(shown)));
    check("a parent that does not fit is refused",
          !resolve_for_landlock(&task, "/proc/new", true, small, sizeof(small), shown,
                                sizeof(shown)));
}

/* The judge's tree, built below, which the walking cases borrow. */
static const char *in_tree(const char *relative);
static void tree_link(const char *relative, const char *target);

/* A child of the suite that sleeps until it is killed, its standard output on output, so that a
 * case has a task whose /proc/self differs from the suite's. Its number is never the fake task's,
 * whose /proc entries the fakes answer for: in a fresh namespace a child may well be given 42. */
static pid_t start_sleeper(int output) {
    pid_t child = 0;
    do {
        if (child == FAKE_PID) {
            waitpid(child, NULL, 0);
        }
        child = fork();
        if (child == 0) {
            dup2(output, STDOUT_FILENO);
            execl("/bin/sleep", "sleep", getpid() == FAKE_PID ? "0" : "60", (char *)NULL);
            _exit(127);
        }
    } while (child == FAKE_PID);
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
    char path[64];
    char name[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)child);
    for (int round = 0; round < 100; round++) {
        if (__real_read_small_file(path, name, sizeof(name), NULL) && strcmp(name, "sleep\n") == 0) {
            break;
        }
        nanosleep(&pause, NULL);
    }
    return child;
}

/* The resolved path of the program a task runs, as /proc/<pid>/exe names it, and whether that path
 * can be reached here. Under an emulator the link may name the emulator, which a container need not
 * be able to reach. */
static bool program_of(pid_t pid, char *out) {
    char link[64];
    char program[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)pid);
    ssize_t length = __real_readlink(link, program, sizeof(program) - 1);
    program[length < 0 ? 0 : length] = '\0';
    return length > 0 && realpath(program, out) != NULL;
}

static void stop_sleeper(pid_t child) {
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
}

/* The suite's own status with its Tgid and Pid lines naming a different task. */
static const char *status_naming(pid_t group, pid_t thread) {
    static char text[PROC_STATUS_LENGTH];
    static char copy[PROC_STATUS_LENGTH];
    size_t used = 0;
    char *state = NULL;
    __real_read_small_file("/proc/self/status", copy, sizeof(copy), NULL);
    for (char *line = strtok_r(copy, "\n", &state); line != NULL; line = strtok_r(NULL, "\n", &state)) {
        if (strncmp(line, "Tgid:", strlen("Tgid:")) == 0) {
            used += (size_t)snprintf(text + used, sizeof(text) - used, "Tgid:\t%d\n", (int)group);
        } else if (strncmp(line, "Pid:", strlen("Pid:")) == 0) {
            used += (size_t)snprintf(text + used, sizeof(text) - used, "Pid:\t%d\n", (int)thread);
        } else {
            used += (size_t)snprintf(text + used, sizeof(text) - used, "%s\n", line);
        }
    }
    return text;
}

static void test_walking_names_as_the_task(void) {
    printf("\nWalking a name as the task walks it\n");
    reset_fakes();
    int pipe_ends[2];
    if (pipe(pipe_ends) != 0) {
        perror("pipe");
        exit(2);
    }
    pid_t child = start_sleeper(pipe_ends[1]);
    char expected[PATH_MAX];
    char out[PATH_MAX];
    struct task_view task = fake_task(status_naming(child, child));
    snprintf(expected, sizeof(expected), "/proc/%d", (int)child);
    check("/proc/self is the task's thread group, not the supervisor's",
          resolve_as_task(&task, "/proc/self", true, out, sizeof(out)) && strcmp(out, expected) == 0);
    snprintf(expected, sizeof(expected), "/proc/%d/task/%d/status", (int)child, (int)child);
    check("/proc/thread-self is the task's thread within it",
          resolve_as_task(&task, "/proc/thread-self/status", true, out, sizeof(out))
              && strcmp(out, expected) == 0);
    char program[PATH_MAX];
    bool reachable = program_of(child, program);
    bool walked = resolve_as_task(&task, "/proc/self/exe", true, out, sizeof(out));
    check("/proc/self/exe leads to the task's program",
          reachable ? walked && strcmp(out, program) == 0 : !walked);
    check("/dev/stdout of a task writing to a pipe leads nowhere a path names",
          !resolve_as_task(&task, "/dev/stdout", true, out, sizeof(out)));
    snprintf(expected, sizeof(expected), "/proc/%d/fd/1", (int)child);
    check("without following the last name, /dev/stdout is the task's descriptor link",
          resolve_as_task(&task, "/dev/fd/1", false, out, sizeof(out)) && strcmp(out, expected) == 0);
    struct task_view nameless = fake_task("Name:\tx\nUid:\t0\n");
    check("a status without a Tgid line refuses a walk through /proc/self",
          !resolve_as_task(&nameless, "/proc/self/status", true, out, sizeof(out)));
    struct task_view garbled = fake_task("Name:\tx\nTgid:\tmany\nPid:\t1\n");
    check("so does one whose Tgid is no number",
          !resolve_as_task(&garbled, "/proc/self/status", true, out, sizeof(out)));
    tree_link("rw/self", "data");
    check("a link named self outside procfs is read as it is",
          resolve_as_task(&task, in_tree("rw/self"), true, out, sizeof(out))
              && strcmp(out, in_tree("rw/data")) == 0);
    unlink(in_tree("rw/self"));
    tree_link("rw/loop", "loop");
    check("a link that leads to itself ends the walk",
          !resolve_as_task(&task, in_tree("rw/loop"), true, out, sizeof(out)));
    check("a link not followed at the end is joined unread",
          resolve_as_task(&task, in_tree("rw/loop"), false, out, sizeof(out))
              && strcmp(out, in_tree("rw/loop")) == 0);
    unlink(in_tree("rw/loop"));
    check("a file used as a directory ends the walk",
          !resolve_as_task(&task, in_tree("rw/data/x"), false, out, sizeof(out)));
    check("a slash after a file ends the walk", !resolve_as_task(&task, in_tree("rw/data/"), false,
                                                                 out, sizeof(out)));
    check("a slash after a directory follows it",
          resolve_as_task(&task, in_tree("rolink/"), false, out, sizeof(out))
              && strcmp(out, in_tree("ro")) == 0);
    check("a link before the last name is always followed",
          resolve_as_task(&task, in_tree("rolink/file"), false, out, sizeof(out))
              && strcmp(out, in_tree("ro/file")) == 0);
    check("a relative link is walked from its own directory",
          (tree_link("rw/up", "../ro"), resolve_as_task(&task, in_tree("rw/up/dir"), true, out,
                                                        sizeof(out)))
              && strcmp(out, in_tree("ro/dir")) == 0);
    check("dot names stay or step up, and a step up from the root stays there",
          resolve_as_task(&task, "/../.././tmp/./", true, out, sizeof(out))
              && strcmp(out, "/tmp") == 0);
    check("the root resolves to itself", resolve_as_task(&task, "///", true, out, sizeof(out))
                                             && strcmp(out, "/") == 0);
    snprintf(fake_refused_access, sizeof(fake_refused_access), "%s", in_tree("ro/dir"));
    fake_refused_mode = X_OK;
    check("a step up from a directory the task may not search ends the walk",
          !resolve_as_task(&task, in_tree("ro/dir/../file"), true, out, sizeof(out)));
    check("and so does a dot in it",
          !resolve_as_task(&task, in_tree("ro/dir/."), true, out, sizeof(out)));
    fake_refused_access[0] = '\0';
    fake_refused_mode = R_OK | W_OK | X_OK;
    check("while a searchable one is stepped up from",
          resolve_as_task(&task, in_tree("ro/dir/../file"), true, out, sizeof(out))
              && strcmp(out, in_tree("ro/file")) == 0);
    fake_readlink(in_tree("rw/up"), "");
    check("a link that cannot be read ends the walk",
          !resolve_as_task(&task, in_tree("rw/up/dir"), true, out, sizeof(out)));
    static char long_target[PATH_MAX];
    memset(long_target, 'l', sizeof(long_target) - 1);
    long_target[sizeof(long_target) - 1] = '\0';
    fake_readlink(in_tree("rw/up"), long_target);
    check("a link whose target fills the buffer ends the walk",
          !resolve_as_task(&task, in_tree("rw/up/dir"), true, out, sizeof(out)));
    long_target[PATH_MAX - 64] = '\0';
    fake_readlink(in_tree("rw/up"), long_target);
    static char long_rest[PATH_MAX];
    snprintf(long_rest, sizeof(long_rest), "%s/%0128d", in_tree("rw/up"), 0);
    check("a link whose target and rest do not fit ends the walk",
          !resolve_as_task(&task, long_rest, true, out, sizeof(out)));
    fake_link_count = 0;
    fake_readlink("/proc/42/root", "/");
    unlink(in_tree("rw/up"));
    char small[4];
    check("a resolved path that does not fit is refused",
          !resolve_as_task(&task, "/proc", true, small, sizeof(small)));
    check("a last name that does not fit is refused",
          !resolve_as_task(&task, "/proc/new", false, small, sizeof(small)));
    check("a rule through /proc/self does not read alike for every process",
          !reads_alike_for_every_process("/proc/self/fd"));
    check("nor one through /dev/stdout", !reads_alike_for_every_process("/dev/stdout"));
    check("nor a relative one", !reads_alike_for_every_process("proc/self"));
    check("a plain path does", reads_alike_for_every_process(in_tree("ro")));
    check("and a missing one does too, the model refusing it on its own",
          reads_alike_for_every_process(in_tree("ro/gone")));
    stop_sleeper(child);
    close(pipe_ends[0]);
    close(pipe_ends[1]);
}

static void test_reading_strings(void) {
    printf("\nWhether the command holds a name\n");
    reset_fakes();
    struct task_view task = fake_task("");
    fake_string(NAME_ADDRESS, "/target");
    check("a name is present", command_string_present(&task, NAME_ADDRESS));
    fake_string(NAME_ADDRESS, "");
    check("an empty one is not", !command_string_present(&task, NAME_ADDRESS));
    check("nor one in unmapped memory", !command_string_present(&task, 0x900000));
    fake_string(NAME_ADDRESS, "/target");
    fake_notification_valid = false;
    check("nor one read for a notification that vanished",
          !command_string_present(&task, NAME_ADDRESS));
}

static void test_reading_small_files(void) {
    printf("\nReading a small file whole\n");
    static char buffer[1 << 16];
    size_t length = 0;
    check("a file is read whole, with its length",
          __real_read_small_file("/proc/self/status", buffer, sizeof(buffer), &length)
              && strstr(buffer, "Uid:") != NULL && length == strlen(buffer));
    check("a file holding NUL bytes is read whole, the NULs counted",
          __real_read_small_file("/proc/self/cmdline", buffer, sizeof(buffer), &length)
              && length > strlen(buffer));
    check("a missing file is refused",
          !__real_read_small_file("/no/such/file", buffer, sizeof(buffer), NULL));
    char small[8];
    check("a file that does not fit is refused",
          !__real_read_small_file("/proc/self/status", small, sizeof(small), NULL));
    check("a directory, which cannot be read, is refused",
          !__real_read_small_file("/proc", buffer, sizeof(buffer), NULL));
}

/* --------------------------------------------------------------------- the judge */

/* The tree the judge cases work on, by the rules the model grants its directories:
 *   ro      read and execute         rw      read, write, create, delete, pipes, symbolic links
 *   rw2     read, write, create, delete, no REFER     rwf, rwf2  the same with REFER
 *   mk      read and create, no delete                monly      create alone
 *   donly   delete alone                              reader     read alone
 *   none    no rule at all
 * and a symbolic link rolink to ro beside them. */
/* The tree's root is kept short, so every path in it fits a PATH_MAX buffer with room to spare. */
static constexpr size_t TREE_ROOT_LENGTH = 256;
static char tree[TREE_ROOT_LENGTH];
static struct policy_model judge_model;
static char task_status[1 << 14];

/* A path in the tree. Several may be held at once, in turn. */
static const char *in_tree(const char *relative) {
    static char paths[8][PATH_MAX];
    static size_t next = 0;
    char *slot = paths[next];
    next = (next + 1) % 8;
    snprintf(slot, PATH_MAX, "%s/%s", tree, relative);
    return slot;
}

static constexpr mode_t TREE_DIRECTORY_MODE = 0700;
static constexpr mode_t TREE_FILE_MODE = 0600;
static constexpr mode_t TREE_PROGRAM_MODE = 0700;

static void tree_directory(const char *relative) {
    if (mkdir(in_tree(relative), TREE_DIRECTORY_MODE) != 0) {
        perror(relative);
        exit(2);
    }
}

static void tree_file(const char *relative, mode_t mode) {
    if (mknod(in_tree(relative), S_IFREG | mode, 0) != 0) {
        perror(relative);
        exit(2);
    }
}

static void tree_link(const char *relative, const char *target) {
    if (symlink(target, in_tree(relative)) != 0) {
        perror(relative);
        exit(2);
    }
}

static void build_tree(void) {
    char made[] = "/tmp/phobos-judge-XXXXXX";
    char resolved[PATH_MAX];
    if (mkdtemp(made) == NULL || realpath(made, resolved) == NULL
        || (size_t)snprintf(tree, sizeof(tree), "%s", resolved) >= sizeof(tree)) {
        perror("mkdtemp");
        exit(2);
    }
    const char *directories[] = {"ro",  "ro/dir", "rw",    "rw/sub", "rw2",    "rwf", "rwf2",
                                 "mk",  "monly",  "donly", "reader", "none",   "none/dir"};
    for (size_t index = 0; index < sizeof(directories) / sizeof(directories[0]); index++) {
        tree_directory(directories[index]);
    }
    const char *files[] = {"ro/file", "rw/data", "rw2/a", "rwf/a", "mk/existing", "donly/f",
                           "none/secret", "reader/data"};
    for (size_t index = 0; index < sizeof(files) / sizeof(files[0]); index++) {
        tree_file(files[index], TREE_FILE_MODE);
    }
    tree_file("ro/exe", TREE_PROGRAM_MODE);
    tree_file("rw/setgid", TREE_FILE_MODE);
    tree_file("rw/setuid", TREE_FILE_MODE);
    if (chmod(in_tree("rw/setgid"), S_ISGID | S_IRWXU | S_IXGRP) != 0
        || chmod(in_tree("rw/setuid"), S_ISUID | S_IRWXU) != 0) {
        perror("chmod");
        exit(2);
    }
    tree_file("none/tool", TREE_PROGRAM_MODE);
    tree_file("reader/tool", TREE_PROGRAM_MODE);
    tree_link("rw/link_to_none", in_tree("none/secret"));
    tree_link("rw/dangling", in_tree("none/missing"));
    tree_link("rolink", in_tree("ro"));
    if (mkfifo(in_tree("none/fifo"), TREE_FILE_MODE) != 0) {
        perror("mkfifo");
        exit(2);
    }
    tree_link("ro/alink", in_tree("none/secret"));
    char *arguments[] = {"enforcer",
                         "--rights=rx",    (char *)in_tree("ro"),
                         "--rights=rwmpld", (char *)in_tree("rw"),
                         "--rights=rwmd",  (char *)in_tree("rw2"),
                         "--rights=rwmdf", (char *)in_tree("rwf"),
                         "--rights=rwmdf", (char *)in_tree("rwf2"),
                         "--",             "/bin/true",
                         NULL};
    char error[256];
    static char argument_copies[16][PATH_MAX];
    for (size_t index = 0; arguments[index] != NULL; index++) {
        snprintf(argument_copies[index], PATH_MAX, "%s", arguments[index]);
        arguments[index] = argument_copies[index];
    }
    if (!build_policy_model(13, arguments, 8, &judge_model, error, sizeof(error))) {
        fprintf(stderr, "the judge's model: %s\n", error);
        exit(2);
    }
}

/* Removes one entry of the tree, deepest first. */
static int remove_entry(const char *path, const struct stat *status, int type, struct FTW *walk) {
    (void)status;
    (void)type;
    (void)walk;
    return remove(path);
}

static void remove_tree(void) {
    nftw(tree, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* The rules mk, monly, donly and reader carry go into a second model, so the first stays the one
 * most cases are about. */
static struct policy_model narrow_model;

static void build_narrow_model(void) {
    static char argument_copies[16][PATH_MAX];
    const char *arguments[] = {"enforcer",
                               "--rights=rwmpld", in_tree("rw"),
                               "--rights=rm",     in_tree("mk"),
                               "--rights=m",      in_tree("monly"),
                               "--rights=d",      in_tree("donly"),
                               "--rights=r",      in_tree("reader"),
                               "--",              "/bin/true",
                               NULL};
    char *copies[16];
    size_t count = 0;
    for (; arguments[count] != NULL; count++) {
        snprintf(argument_copies[count], PATH_MAX, "%s", arguments[count]);
        copies[count] = argument_copies[count];
    }
    copies[count] = NULL;
    char error[256];
    if (!build_policy_model((int)count, copies, 8, &narrow_model, error, sizeof(error))) {
        fprintf(stderr, "the narrow model: %s\n", error);
        exit(2);
    }
}

/* The exact line for one refusal of one plain path. */
static const char *line_for(const char *verb, const char *noun, const char *object) {
    static char line[PATH_MAX * 3];
    snprintf(line, sizeof(line),
             "Phobos Security Error: the program tried to illegally %s the %s '%s' but was "
             "blocked by Phobos.\n",
             verb, noun, object);
    return line;
}

/* Judges one native call against a model, with the names already placed in memory, and answers
 * what it printed. */
static const char *judged_with(const struct policy_model *model, struct seccomp_data data) {
    struct access_request request;
    struct task_view task = fake_task(task_status);
    decode_trapped_call(&data, &request);
    reset_report_for_tests();
    capture_stderr_begin();
    judge_and_report(&task, &request, model);
    return capture_stderr_end();
}

static const char *judged(struct seccomp_data data) {
    return judged_with(&judge_model, data);
}

/* An openat of one absolute name with the given flags. */
static const char *judged_open(const char *path, int flags) {
    fake_string(NAME_ADDRESS, path);
    return judged(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, (uint64_t)flags, 0, 0));
}

static bool silent(const char *text) {
    return strcmp(text, "") == 0;
}

static void test_judging_opens(void) {
    printf("\nAn open\n");
    reset_fakes();
    check("a granted read is silent", silent(judged_open(in_tree("ro/file"), O_RDONLY)));
    check("a refused read names the file",
          strcmp(judged_open(in_tree("none/secret"), O_RDONLY),
                 line_for("read", "File", in_tree("none/secret"))) == 0);
    check("a refused write names the file",
          strcmp(judged_open(in_tree("ro/file"), O_WRONLY),
                 line_for("write", "File", in_tree("ro/file"))) == 0);
    check("a refused read and write is a write",
          strcmp(judged_open(in_tree("ro/file"), O_RDWR),
                 line_for("write", "File", in_tree("ro/file"))) == 0);
    check("O_TRUNC is a write",
          strcmp(judged_open(in_tree("ro/file"), O_RDONLY | O_TRUNC),
                 line_for("write", "File", in_tree("ro/file"))) == 0);
    check("a granted write is silent", silent(judged_open(in_tree("rw/data"), O_RDWR | O_APPEND)));
    check("a refused read of a directory names the directory",
          strcmp(judged_open(in_tree("none/dir"), O_RDONLY | O_DIRECTORY),
                 line_for("read", "Directory", in_tree("none/dir"))) == 0);
    check("a refused read of a named pipe reads a File, as READ_FILE words it",
          strcmp(judged_open(in_tree("none/fifo"), O_RDONLY | O_NONBLOCK),
                 line_for("read", "File", in_tree("none/fifo"))) == 0);
    check("a refused create names the new file",
          strcmp(judged_open(in_tree("ro/new"), O_WRONLY | O_CREAT),
                 line_for("create", "File", in_tree("ro/new"))) == 0);
    check("a granted create is silent", silent(judged_open(in_tree("rw/new"), O_WRONLY | O_CREAT)));
    fake_string(NAME_ADDRESS, "out.txt");
    fake_readlink("/proc/42/cwd", in_tree("none"));
    check("a relative create under a refused directory names it absolutely",
          strcmp(judged(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS,
                                    O_WRONLY | O_CREAT, 0, 0)),
                 line_for("create", "File", in_tree("none/out.txt"))) == 0);
    check("a symbolic link names what it leads to, and the name the program gave",
          strstr(judged_open(in_tree("rw/link_to_none"), O_RDONLY), "' (named as '") != NULL);
    char expected[PATH_MAX * 3];
    snprintf(expected, sizeof(expected),
             "Phobos Security Error: the program tried to illegally read the File '%s' (named as "
             "'%s') but was blocked by Phobos.\n",
             in_tree("none/secret"), in_tree("rw/link_to_none"));
    check("and the line is byte exact",
          strcmp(judged_open(in_tree("rw/link_to_none"), O_RDONLY), expected) == 0);
    fake_string(NAME_ADDRESS, in_tree("mk/new"));
    check("a create where only creation is granted is refused as a write",
          strcmp(judged_with(&narrow_model, native_call(__NR_openat, AT_FDCWD_ARGUMENT,
                                                        NAME_ADDRESS, O_WRONLY | O_CREAT, 0, 0)),
                 line_for("write", "File", in_tree("mk/new"))) == 0);
    fake_string(NAME_ADDRESS, in_tree("monly/new"));
    check("a reading create where only creation is granted is refused as a read",
          strcmp(judged_with(&narrow_model, native_call(__NR_openat, AT_FDCWD_ARGUMENT,
                                                        NAME_ADDRESS, O_RDONLY | O_CREAT, 0, 0)),
                 line_for("read", "File", in_tree("monly/new"))) == 0);
    fake_string(NAME_ADDRESS, in_tree("mk/new"));
    check("a reading create where creation and reading are granted is silent",
          silent(judged_with(&narrow_model, native_call(__NR_openat, AT_FDCWD_ARGUMENT,
                                                        NAME_ADDRESS, O_RDONLY | O_CREAT, 0, 0))));
}

static void test_opens_that_stay_silent(void) {
    printf("\nAn open that stays silent although the model refuses it\n");
    reset_fakes();
    const char *secret = in_tree("none/secret");
    check("a missing name without O_CREAT", silent(judged_open(in_tree("none/missing"), O_RDONLY)));
    check("O_PATH", silent(judged_open(secret, O_PATH)));
    check("O_TMPFILE", silent(judged_open(in_tree("none"), O_TMPFILE | O_RDWR)));
    check("O_NOATIME", silent(judged_open(secret, O_RDONLY | O_NOATIME)));
    check("an unknown flag", silent(judged_open(secret, O_RDONLY | 0x40000000)));
    check("O_CREAT and O_EXCL on an existing name",
          silent(judged_open(secret, O_WRONLY | O_CREAT | O_EXCL)));
    check("O_NOFOLLOW on a final symbolic link",
          silent(judged_open(in_tree("rw/link_to_none"), O_RDONLY | O_NOFOLLOW)));
    check("O_CREAT on a dangling symbolic link",
          silent(judged_open(in_tree("rw/dangling"), O_WRONLY | O_CREAT)));
    check("O_DIRECTORY on a file", silent(judged_open(secret, O_RDONLY | O_DIRECTORY)));
    check("a write of a directory", silent(judged_open(in_tree("none/dir"), O_WRONLY)));
    check("O_CREAT on an existing directory",
          silent(judged_open(in_tree("none/dir"), O_RDONLY | O_CREAT)));
    check("both access mode bits", silent(judged_open(secret, O_ACCMODE)));
    check("a create with a trailing slash",
          silent(judged_open(in_tree("ro/newdir/"), O_WRONLY | O_CREAT)));
    check("a create with O_DIRECTORY",
          silent(judged_open(in_tree("ro/new"), O_RDONLY | O_CREAT | O_DIRECTORY)));
    check("a create under a missing directory",
          silent(judged_open(in_tree("ro/missing/new"), O_WRONLY | O_CREAT)));
    check("a create under a file", silent(judged_open(in_tree("ro/file/new"), O_WRONLY | O_CREAT)));
    snprintf(fake_refused_access, sizeof(fake_refused_access), "%s", secret);
    check("a file the mode refuses", silent(judged_open(secret, O_RDONLY)));
    snprintf(fake_refused_access, sizeof(fake_refused_access), "%s", in_tree("ro"));
    check("a create in a directory the mode keeps the task from searching",
          silent(judged_open(in_tree("ro/new"), O_WRONLY | O_CREAT)));
    fake_refused_access[0] = '\0';
    snprintf(fake_read_only_mount, sizeof(fake_read_only_mount), "%s", in_tree("ro"));
    check("a write on a read-only mount", silent(judged_open(in_tree("ro/file"), O_WRONLY)));
    check("a create on a read-only mount",
          silent(judged_open(in_tree("ro/new"), O_WRONLY | O_CREAT)));
    snprintf(fake_read_only_mount, sizeof(fake_read_only_mount), "%s", in_tree("none"));
    check("but a refused read on a read-only mount is still a line",
          !silent(judged_open(secret, O_RDONLY)));
    fake_read_only_mount[0] = '\0';
    int socket_descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", in_tree("none/sock"));
    bool bound = bind(socket_descriptor, (struct sockaddr *)&address, sizeof(address)) == 0;
    check("a socket file", bound && silent(judged_open(in_tree("none/sock"), O_RDONLY)));
    close(socket_descriptor);
    unlink(in_tree("none/sock"));
    fake_readlink(in_tree("rw/link_to_none"), "");
    check("a file whose link can no longer be read",
          silent(judged_open(in_tree("rw/link_to_none"), O_RDONLY)));
    fake_link_count = 0;
    fake_readlink("/proc/42/root", "/");
    struct access_request arming;
    struct seccomp_data restrict_self = native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0,
                                                    0, 0);
    decode_trapped_call(&restrict_self, &arming);
    struct task_view task = fake_task(task_status);
    capture_stderr_begin();
    judge_and_report(&task, &arming, &judge_model);
    check("an arming call, which is no path call", silent(capture_stderr_end()));
}

static void test_tasks_that_are_not_judged(void) {
    printf("\nA task the supervisor cannot speak for\n");
    reset_fakes();
    const char *secret = in_tree("none/secret");
    static char other_user[1 << 14];
    snprintf(other_user, sizeof(other_user), "%s", task_status);
    char *uid = strstr(other_user, "Uid:");
    uid[strlen("Uid:") + 1] = uid[strlen("Uid:") + 1] == '9' ? '8' : '9';
    fake_string(NAME_ADDRESS, secret);
    struct access_request request;
    struct seccomp_data data = native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY,
                                           0, 0);
    decode_trapped_call(&data, &request);
    struct task_view task = fake_task(other_user);
    capture_stderr_begin();
    judge_and_report(&task, &request, &judge_model);
    check("a task with other credentials", silent(capture_stderr_end()));
    task = fake_task("Name:\tx");
    capture_stderr_begin();
    judge_and_report(&task, &request, &judge_model);
    check("a task whose status names no credentials", silent(capture_stderr_end()));
    fake_readlink("/proc/42/root", "/srv/chroot");
    check("a task with another root", silent(judged_open(secret, O_RDONLY)));
    fake_link_count = 0;
    check("a task whose root cannot be read", silent(judged_open(secret, O_RDONLY)));
    reset_fakes();
    fake_notification_valid = false;
    check("a notification that vanished", silent(judged_open(secret, O_RDONLY)));
    reset_fakes();
    fake_own_status = "Name:\tsupervisor\n";
    check("a supervisor whose own status names no credentials",
          silent(judged_open(secret, O_RDONLY)));
}

static void test_judging_openat2(void) {
    printf("\nAn openat2\n");
    reset_fakes();
    struct open_how how = {.flags = O_RDONLY, .mode = 0, .resolve = 0};
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    fake_memory(OTHER_NAME_ADDRESS, &how, sizeof(how));
    struct seccomp_data data = native_call(__NR_openat2, AT_FDCWD_ARGUMENT, NAME_ADDRESS,
                                           OTHER_NAME_ADDRESS, sizeof(how), 0);
    check("a refused read is a line",
          strcmp(judged(data), line_for("read", "File", in_tree("none/secret"))) == 0);
    how.resolve = RESOLVE_BENEATH;
    fake_memory(OTHER_NAME_ADDRESS, &how, sizeof(how));
    check("a resolve flag stays silent", silent(judged(data)));
    how.resolve = 0;
    how.flags = (uint64_t)1 << 40;
    fake_memory(OTHER_NAME_ADDRESS, &how, sizeof(how));
    check("flags beyond an int stay silent", silent(judged(data)));
    data.args[3] = sizeof(how) + 8;
    check("another open_how size stays silent", silent(judged(data)));
    data.args[3] = sizeof(how);
    data.args[2] = 0x900000;
    check("an open_how that cannot be read stays silent", silent(judged(data)));
}

static void test_judging_execution(void) {
    printf("\nAn execve\n");
    reset_fakes();
    fake_string(NAME_ADDRESS, in_tree("none/tool"));
    struct seccomp_data execve_call = native_call(__NR_execve, NAME_ADDRESS, 0, 0, 0, 0);
    check("a refused execute names the file",
          strcmp(judged(execve_call), line_for("execute", "File", in_tree("none/tool"))) == 0);
    fake_string(NAME_ADDRESS, in_tree("reader/tool"));
    check("a file that may be read but not executed is refused as an execute",
          strcmp(judged_with(&narrow_model, execve_call),
                 line_for("execute", "File", in_tree("reader/tool"))) == 0);
    fake_string(NAME_ADDRESS, in_tree("ro/exe"));
    check("a granted execute is silent", silent(judged(execve_call)));
    fake_string(NAME_ADDRESS, in_tree("none/tool"));
    check("execveat with AT_EMPTY_PATH stays silent",
          silent(judged(native_call(__NR_execveat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, 0, 0,
                                    AT_EMPTY_PATH))));
    check("execveat with AT_SYMLINK_NOFOLLOW on a file is judged",
          !silent(judged(native_call(__NR_execveat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, 0, 0,
                                     AT_SYMLINK_NOFOLLOW))));
    fake_string(NAME_ADDRESS, in_tree("rw/link_to_none"));
    check("execveat with AT_SYMLINK_NOFOLLOW on a final link stays silent",
          silent(judged(native_call(__NR_execveat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, 0, 0,
                                    AT_SYMLINK_NOFOLLOW))));
    fake_string(NAME_ADDRESS, in_tree("rw/dangling"));
    check("a dangling link stays silent", silent(judged(execve_call)));
    fake_string(NAME_ADDRESS, in_tree("none/dir"));
    check("a directory stays silent", silent(judged(execve_call)));
    fake_string(NAME_ADDRESS, in_tree("none/missing"));
    check("a missing file stays silent", silent(judged(execve_call)));
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    check("a file without an execute bit stays silent", silent(judged(execve_call)));
    fake_string(NAME_ADDRESS, in_tree("none/tool"));
    snprintf(fake_noexec_mount, sizeof(fake_noexec_mount), "%s", in_tree("none"));
    check("a file on a noexec mount stays silent", silent(judged(execve_call)));
}

/* A call that names one path, with the call's other arguments after the name. */
static const char *judged_name_call(int number, const char *path, uint64_t argument) {
    fake_string(NAME_ADDRESS, path);
    return judged(native_call(number, AT_FDCWD_ARGUMENT, NAME_ADDRESS, argument, 0, 0));
}

static void test_judging_creation(void) {
    printf("\nA mkdir, mknod and symlink\n");
    reset_fakes();
    check("a refused mkdir names the new directory",
          strcmp(judged_name_call(__NR_mkdirat, in_tree("ro/newdir"), FILE_MODE),
                 line_for("create", "Directory", in_tree("ro/newdir"))) == 0);
    check("a mkdir with a trailing slash names it without",
          strcmp(judged_name_call(__NR_mkdirat, in_tree("ro/newdir//"), FILE_MODE),
                 line_for("create", "Directory", in_tree("ro/newdir"))) == 0);
    fake_string(NAME_ADDRESS, "dir/new");
    fake_readlink("/proc/42/cwd", in_tree("ro"));
    check("a relative mkdir names the new directory, not its parent",
          strcmp(judged(native_call(__NR_mkdirat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, FILE_MODE, 0,
                                    0)),
                 line_for("create", "Directory", in_tree("ro/dir/new"))) == 0);
    check("a granted mkdir is silent",
          silent(judged_name_call(__NR_mkdirat, in_tree("rw/newdir"), FILE_MODE)));
    check("a mkdir of an existing name is silent",
          silent(judged_name_call(__NR_mkdirat, in_tree("ro/dir"), FILE_MODE)));
    check("a mkdir under a missing parent is silent",
          silent(judged_name_call(__NR_mkdirat, in_tree("ro/missing/new"), FILE_MODE)));
    check("a refused named pipe",
          strcmp(judged_name_call(__NR_mknodat, in_tree("ro/fifo"), S_IFIFO | FILE_MODE),
                 line_for("create", "Named Pipe", in_tree("ro/fifo"))) == 0);
    check("a granted named pipe is silent",
          silent(judged_name_call(__NR_mknodat, in_tree("rw/fifo"), S_IFIFO | FILE_MODE)));
    check("a refused socket file",
          strcmp(judged_name_call(__NR_mknodat, in_tree("ro/sock"), S_IFSOCK | FILE_MODE),
                 line_for("create", "Socket File", in_tree("ro/sock"))) == 0);
    check("a refused character device",
          strcmp(judged_name_call(__NR_mknodat, in_tree("rw/tty"), S_IFCHR | FILE_MODE),
                 line_for("create", "Device", in_tree("rw/tty"))) == 0);
    check("a refused block device",
          strcmp(judged_name_call(__NR_mknodat, in_tree("rw/disk"), S_IFBLK | FILE_MODE),
                 line_for("create", "Device", in_tree("rw/disk"))) == 0);
    check("a mknod with no type is a regular file",
          strcmp(judged_name_call(__NR_mknodat, in_tree("ro/plain"), FILE_MODE),
                 line_for("create", "File", in_tree("ro/plain"))) == 0);
    check("a mknod of a regular file",
          strcmp(judged_name_call(__NR_mknodat, in_tree("ro/plain"), S_IFREG | FILE_MODE),
                 line_for("create", "File", in_tree("ro/plain"))) == 0);
    check("a mknod of a directory is silent",
          silent(judged_name_call(__NR_mknodat, in_tree("ro/x"), S_IFDIR | FILE_MODE)));
    check("a mknod of a symbolic link type is silent",
          silent(judged_name_call(__NR_mknodat, in_tree("ro/x"), S_IFLNK | FILE_MODE)));
    check("a mknod with a trailing slash is silent",
          silent(judged_name_call(__NR_mknodat, in_tree("ro/fifo/"), S_IFIFO | FILE_MODE)));
    fake_string(OTHER_NAME_ADDRESS, "/target");
    fake_string(NAME_ADDRESS, in_tree("ro/link"));
    check("a refused symbolic link",
          strcmp(judged(native_call(__NR_symlinkat, OTHER_NAME_ADDRESS, AT_FDCWD_ARGUMENT,
                                    NAME_ADDRESS, 0, 0)),
                 line_for("create", "Symbolic Link", in_tree("ro/link"))) == 0);
    fake_string(NAME_ADDRESS, in_tree("rw/link"));
    check("a granted symbolic link is silent",
          silent(judged(native_call(__NR_symlinkat, OTHER_NAME_ADDRESS, AT_FDCWD_ARGUMENT,
                                    NAME_ADDRESS, 0, 0))));
}

static void test_judging_removal(void) {
    printf("\nAn unlink and rmdir\n");
    reset_fakes();
    check("a refused unlink names the file",
          strcmp(judged_name_call(__NR_unlinkat, in_tree("ro/file"), 0),
                 line_for("delete", "File", in_tree("ro/file"))) == 0);
    check("a refused rmdir names the directory",
          strcmp(judged_name_call(__NR_unlinkat, in_tree("ro/dir/"), AT_REMOVEDIR),
                 line_for("delete", "Directory", in_tree("ro/dir"))) == 0);
    check("a granted unlink is silent", silent(judged_name_call(__NR_unlinkat, in_tree("rw/data"), 0)));
    char expected[PATH_MAX * 3];
    snprintf(expected, sizeof(expected),
             "Phobos Security Error: the program tried to illegally delete the File '%s' (named "
             "as '%s') but was blocked by Phobos.\n",
             in_tree("ro/file"), in_tree("rolink/file"));
    check("an unlink through a linked parent names the resolved parent and the name given",
          strcmp(judged_name_call(__NR_unlinkat, in_tree("rolink/file"), 0), expected) == 0);
    check("an unlink of a symbolic link names the link, not what it leads to",
          strcmp(judged_name_call(__NR_unlinkat, in_tree("ro/alink"), 0),
                 line_for("delete", "File", in_tree("ro/alink"))) == 0);
    check("a granted unlink of a symbolic link is silent",
          silent(judged_name_call(__NR_unlinkat, in_tree("rw/link_to_none"), 0)));
    check("an unlink of a directory is silent",
          silent(judged_name_call(__NR_unlinkat, in_tree("ro/dir"), 0)));
    check("an rmdir of a file is silent",
          silent(judged_name_call(__NR_unlinkat, in_tree("ro/file"), AT_REMOVEDIR)));
    check("an unlink with a trailing slash is silent",
          silent(judged_name_call(__NR_unlinkat, in_tree("ro/file/"), 0)));
    check("an unknown flag is silent",
          silent(judged_name_call(__NR_unlinkat, in_tree("ro/file"), 0x8000)));
    check("a missing name is silent", silent(judged_name_call(__NR_unlinkat, in_tree("ro/gone"), 0)));
    check("a dot entry is silent",
          silent(judged_name_call(__NR_unlinkat, in_tree("ro/dir/.."), AT_REMOVEDIR)));
}

/* A call that names two paths, as rename and link do. */
static const char *judged_two_names(const struct policy_model *model, int number,
                                    const char *from, const char *to, uint64_t flags) {
    fake_string(NAME_ADDRESS, from);
    fake_string(OTHER_NAME_ADDRESS, to);
    return judged_with(model, native_call(number, AT_FDCWD_ARGUMENT, NAME_ADDRESS,
                                          AT_FDCWD_ARGUMENT, OTHER_NAME_ADDRESS, flags));
}

/* The exact line for a move or a link. */
static const char *two_path_line(const char *verb, const char *noun, const char *from,
                                 const char *to) {
    static char line[PATH_MAX * 3];
    snprintf(line, sizeof(line),
             "Phobos Security Error: the program tried to illegally %s the %s '%s' to '%s' but was "
             "blocked by Phobos.\n",
             verb, noun, from, to);
    return line;
}

static void test_judging_renames(void) {
    printf("\nA rename\n");
    reset_fakes();
    check("a source that may not be removed is a delete",
          strcmp(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                  in_tree("ro/file2"), 0),
                 line_for("delete", "File", in_tree("ro/file"))) == 0);
    check("a destination that may not be created is a create",
          strcmp(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw/data"),
                                  in_tree("ro/moved"), 0),
                 line_for("create", "File", in_tree("ro/moved"))) == 0);
    check("a rename within one directory needs no REFER",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw2/a"),
                                  in_tree("rw2/b"), 0)));
    check("a rename across directories without REFER is a move",
          strcmp(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw2/a"),
                                  in_tree("rw/a"), 0),
                 two_path_line("move", "File", in_tree("rw2/a"), in_tree("rw/a"))) == 0);
    check("a rename across directories with REFER on both is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("rwf/a"),
                                  in_tree("rwf2/a"), 0)));
    check("a directory is moved as a directory",
          strcmp(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw/sub"),
                                  in_tree("rw2/sub"), 0),
                 two_path_line("move", "Directory", in_tree("rw/sub"), in_tree("rw2/sub"))) == 0);
    check("an existing destination that may not be removed is a delete",
          strcmp(judged_two_names(&narrow_model, __NR_renameat2, in_tree("rw/data"),
                                  in_tree("mk/existing"), 0),
                 line_for("delete", "File", in_tree("mk/existing"))) == 0);
    check("an exchange whose source directory may not create the other is a create",
          strcmp(judged_two_names(&narrow_model, __NR_renameat2, in_tree("donly/f"),
                                  in_tree("rw/data"), RENAME_EXCHANGE),
                 line_for("create", "File", in_tree("donly/f"))) == 0);
    check("RENAME_NOREPLACE onto an existing name is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                  in_tree("rw/data"), RENAME_NOREPLACE)));
    check("RENAME_NOREPLACE onto a new name is judged",
          !silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                   in_tree("rw/fresh"), RENAME_NOREPLACE)));
    check("RENAME_EXCHANGE with no destination is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                  in_tree("rw/fresh"), RENAME_EXCHANGE)));
    check("both flags at once are silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                  in_tree("rw/fresh"), RENAME_NOREPLACE | RENAME_EXCHANGE)));
    check("RENAME_WHITEOUT is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                  in_tree("rw/fresh"), RENAME_WHITEOUT)));
    check("a directory over a file is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/dir"),
                                  in_tree("rw/data"), 0)));
    check("a missing source is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/gone"),
                                  in_tree("rw/fresh"), 0)));
    check("a file named with a trailing slash is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                  in_tree("rw/fresh/"), 0)));
    check("a directory named with a trailing slash is judged",
          !silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/dir/"),
                                   in_tree("rw/fresh/"), 0)));
    check("a directory into its own subtree is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro"),
                                  in_tree("ro/dir/inside"), 0)));
    check("a name onto its own ancestor is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/dir"), in_tree("ro"),
                                  0)));
    snprintf(fake_other_mount, sizeof(fake_other_mount), "%s", in_tree("rw"));
    check("a rename across mounts is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw2/a"),
                                  in_tree("rw/a"), 0)));
    fake_other_mount[0] = '\0';
    fake_statx_fails = true;
    check("a rename whose mounts cannot be told is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw2/a"),
                                  in_tree("rw/a"), 0)));
    fake_statx_fails = false;
    check("a rename whose destination parent is missing is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("ro/file"),
                                  in_tree("rw/missing/x"), 0)));
}

static void test_judging_links(void) {
    printf("\nA hard link\n");
    reset_fakes();
    check("a destination that may not be created is a create",
          strcmp(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                  in_tree("ro/hard"), 0),
                 line_for("create", "File", in_tree("ro/hard"))) == 0);
    check("a link across directories without REFER is a link",
          strcmp(judged_two_names(&judge_model, __NR_linkat, in_tree("rw2/a"), in_tree("rw/b"), 0),
                 two_path_line("link", "File", in_tree("rw2/a"), in_tree("rw/b"))) == 0);
    check("a link from a directory with REFER to one without is a link",
          strcmp(judged_two_names(&judge_model, __NR_linkat, in_tree("rwf/a"), in_tree("rw/b"), 0),
                 two_path_line("link", "File", in_tree("rwf/a"), in_tree("rw/b"))) == 0);
    check("a link within one directory is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                  in_tree("rw/hard"), 0)));
    check("a link from a directory that may not be changed is still judged",
          !silent(judged_two_names(&judge_model, __NR_linkat, in_tree("ro/file"),
                                   in_tree("rw/hard"), 0)));
    check("AT_SYMLINK_FOLLOW is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                  in_tree("ro/hard"), AT_SYMLINK_FOLLOW)));
    check("AT_EMPTY_PATH is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                  in_tree("ro/hard"), AT_EMPTY_PATH)));
    check("an existing destination is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                  in_tree("ro/file"), 0)));
    check("a directory source is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/sub"),
                                  in_tree("ro/hard"), 0)));
    check("a source that cannot be examined is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data/.."),
                                  in_tree("ro/hard"), 0)));
    check("a source whose parent does not resolve is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rolink/.."),
                                  in_tree("ro/hard"), 0)));
    static char unprivileged[1 << 12];
    snprintf(unprivileged, sizeof(unprivileged),
             "Uid:\t1\t1\t1\t1\nGid:\t1\t1\t1\t1\nGroups:\t\nCapEff:\t0000000000000000\n");
    fake_own_status = unprivileged;
    reset_judge_for_tests();
    fake_euid_set = true;
    fake_euid = 4242;
    snprintf(task_status, sizeof(task_status), "%s", unprivileged);
    check("a file another user owns, readable and writable, may still be linked",
          !silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                   in_tree("ro/hard"), 0)));
    check("a set-group-id executable another user owns is no safe source, so its link is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/setgid"),
                                  in_tree("ro/hard"), 0)));
    check("nor is a set-user-id one",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/setuid"),
                                  in_tree("ro/hard"), 0)));
    snprintf(fake_refused_access, sizeof(fake_refused_access), "%s", in_tree("rw/data"));
    check("one the mode keeps from this user may not be linked, so the link is silent",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                  in_tree("ro/hard"), 0)));
    fake_own_status = "Uid:\t1\t1\t1\t1\nGid:\t1\t1\t1\t1\nGroups:\t\n";
    reset_judge_for_tests();
    snprintf(task_status, sizeof(task_status), "%s", fake_own_status);
    check("a supervisor whose own status names no capabilities judges no task",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"),
                                  in_tree("ro/hard"), 0)));
    reset_fakes();
    __real_read_small_file("/proc/self/status", task_status, sizeof(task_status), NULL);
}

static void test_judging_truncation(void) {
    printf("\nA truncate\n");
    reset_fakes();
    fake_string(NAME_ADDRESS, in_tree("ro/file"));
    struct seccomp_data call = native_call(__NR_truncate, NAME_ADDRESS, 0, 0, 0, 0);
    check("a refused truncate is a write",
          strcmp(judged(call), line_for("write", "File", in_tree("ro/file"))) == 0);
    fake_string(NAME_ADDRESS, in_tree("rw/data"));
    check("a granted truncate is silent", silent(judged(call)));
    fake_string(NAME_ADDRESS, in_tree("ro/file"));
    call.args[1] = (uint64_t)-1;
    check("a negative length is silent", silent(judged(call)));
    call.args[1] = 0;
    fake_string(NAME_ADDRESS, in_tree("ro/dir"));
    check("a directory is silent", silent(judged(call)));
    fake_string(NAME_ADDRESS, in_tree("ro/gone"));
    check("a missing file is silent", silent(judged(call)));
    fake_string(NAME_ADDRESS, in_tree("ro/file"));
    snprintf(fake_read_only_mount, sizeof(fake_read_only_mount), "%s", in_tree("ro"));
    check("a file on a read-only mount is silent", silent(judged(call)));
    fake_read_only_mount[0] = '\0';
    snprintf(fake_refused_access, sizeof(fake_refused_access), "%s", in_tree("ro/file"));
    check("a file the mode refuses to write is silent", silent(judged(call)));
    reset_fakes();
    struct policy_model version_two = judge_model;
    version_two.handled_filesystem = filesystem_rights_for_version(2);
    check("below version 3 a truncate is not handled, so it is silent",
          silent(judged_with(&version_two, call)));
    check("while a write is still refused at version 2",
          strcmp(judged_with(&version_two, (fake_string(NAME_ADDRESS, in_tree("ro/file")),
                                            native_call(__NR_openat, AT_FDCWD_ARGUMENT,
                                                        NAME_ADDRESS, O_WRONLY | O_TRUNC, 0, 0))),
                 line_for("write", "File", in_tree("ro/file"))) == 0);
}

static void test_judging_as_the_task(void) {
    printf("\nA name the task resolves differently from the supervisor\n");
    reset_fakes();
    int output = open(in_tree("none/child-output"), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                      TREE_FILE_MODE);
    int pipe_ends[2];
    if (output < 0 || pipe(pipe_ends) != 0) {
        perror("child output");
        exit(2);
    }
    pid_t child = start_sleeper(output);
    pid_t piped = start_sleeper(pipe_ends[1]);
    char resolved_program[PATH_MAX];
    bool reachable = program_of(child, resolved_program);
    snprintf(task_status, sizeof(task_status), "%s", status_naming(child, child));
    char expected[PATH_MAX * 3];
    fake_string(NAME_ADDRESS, "/proc/self/exe");
    snprintf(expected, sizeof(expected),
             "Phobos Security Error: the program tried to illegally execute the File '%s' (named "
             "as '/proc/self/exe') but was blocked by Phobos.\n",
             resolved_program);
    const char *executed = judged(native_call(__NR_execve, NAME_ADDRESS, 0, 0, 0, 0));
    check("an execve of /proc/self/exe names the task's program",
          reachable ? strcmp(executed, expected) == 0 : silent(executed));
    snprintf(expected, sizeof(expected),
             "Phobos Security Error: the program tried to illegally write the File '%s' (named "
             "as '/dev/stdout') but was blocked by Phobos.\n",
             in_tree("none/child-output"));
    check("a write of /dev/stdout names the file the task's output goes to",
          strcmp(judged_open("/dev/stdout", O_WRONLY), expected) == 0);
    snprintf(expected, sizeof(expected),
             "Phobos Security Error: the program tried to illegally read the Directory "
             "'/proc/%d/fd' (named as '/proc/self/fd') but was blocked by Phobos.\n",
             (int)child);
    check("a read of /proc/self/fd names the task's descriptors, not the supervisor's",
          strcmp(judged_open("/proc/self/fd", O_RDONLY | O_DIRECTORY), expected) == 0);
    snprintf(task_status, sizeof(task_status), "%s", status_naming(piped, piped));
    check("a write of /dev/stdout by a task writing to a pipe is silent",
          silent(judged_open("/dev/stdout", O_WRONLY)));
    stop_sleeper(child);
    stop_sleeper(piped);
    close(output);
    close(pipe_ends[0]);
    close(pipe_ends[1]);
    unlink(in_tree("none/child-output"));
    __real_read_small_file("/proc/self/status", task_status, sizeof(task_status), NULL);
}

/* Refuses, in turn, the file mode of the tree's read-only directory with only the given bits. */
static void refuse_mode_on(const char *relative, int bits) {
    snprintf(fake_refused_access, sizeof(fake_refused_access), "%s", in_tree(relative));
    fake_refused_mode = bits;
}

static void test_judging_what_the_kernel_checks_first(void) {
    printf("\nWhat the kernel checks before Landlock, and what only after it\n");
    reset_fakes();
    refuse_mode_on("ro", W_OK);
    check("a create where the mode refuses writing the directory is still Landlock's refusal",
          strcmp(judged_open(in_tree("ro/new"), O_WRONLY | O_CREAT),
                 line_for("create", "File", in_tree("ro/new"))) == 0);
    check("and so is a mkdir there",
          strcmp(judged_name_call(__NR_mkdirat, in_tree("ro/newdir"), FILE_MODE),
                 line_for("create", "Directory", in_tree("ro/newdir"))) == 0);
    check("and an unlink there",
          strcmp(judged_name_call(__NR_unlinkat, in_tree("ro/file"), 0),
                 line_for("delete", "File", in_tree("ro/file"))) == 0);
    refuse_mode_on("ro", X_OK);
    check("while a directory the mode keeps the task from searching is silent",
          silent(judged_open(in_tree("ro/new"), O_WRONLY | O_CREAT)));
    reset_fakes();
    snprintf(fake_other_mount, sizeof(fake_other_mount), "%s", in_tree("rw/data"));
    check("a link whose source is a mount of its own is silent, the kernel answering EXDEV",
          silent(judged_two_names(&judge_model, __NR_linkat, in_tree("rw/data"), in_tree("ro/hard"),
                                  0)));
    check("while a rename of it is judged by its parent's mount",
          strcmp(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw/data"),
                                  in_tree("ro/moved"), 0),
                 line_for("create", "File", in_tree("ro/moved"))) == 0);
    fake_other_mount[0] = '\0';
    fake_string(NAME_ADDRESS, in_tree("rw/data"));
    check("a rename whose second name cannot be read is silent",
          silent(judged(native_call(__NR_renameat2, AT_FDCWD_ARGUMENT, NAME_ADDRESS,
                                    AT_FDCWD_ARGUMENT, 0x900000, 0))));
    fake_string(OTHER_NAME_ADDRESS, "");
    fake_string(NAME_ADDRESS, in_tree("ro/link"));
    check("a symbolic link with an empty target is silent",
          silent(judged(native_call(__NR_symlinkat, OTHER_NAME_ADDRESS, AT_FDCWD_ARGUMENT,
                                    NAME_ADDRESS, 0, 0))));
    check("and one whose target cannot be read",
          silent(judged(native_call(__NR_symlinkat, 0x900000, AT_FDCWD_ARGUMENT, NAME_ADDRESS, 0,
                                    0))));
    static char long_name[PATH_MAX];
    snprintf(long_name, sizeof(long_name), "%s/%0300d", in_tree("ro"), 0);
    check("a last name longer than a name may be is silent for a mkdir",
          silent(judged_name_call(__NR_mkdirat, long_name, FILE_MODE)));
    check("and for a creating open", silent(judged_open(long_name, O_WRONLY | O_CREAT)));
    check("and as a rename's destination",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("rw/data"), long_name, 0)));
    check("O_TRUNC on a directory is silent",
          silent(judged_open(in_tree("none/dir"), O_RDONLY | O_TRUNC)));
    refuse_mode_on("none/fifo", W_OK);
    check("O_TRUNC on a named pipe the mode will not let be written is silent",
          silent(judged_open(in_tree("none/fifo"), O_RDONLY | O_NONBLOCK | O_TRUNC)));
    reset_fakes();
    check("a truncating read that Landlock refuses to read is a read, the truncation coming after",
          strcmp(judged_open(in_tree("none/secret"), O_RDONLY | O_TRUNC),
                 line_for("read", "File", in_tree("none/secret"))) == 0);
    struct open_how how = {.flags = O_RDONLY, .mode = 0644, .resolve = 0};
    struct seccomp_data openat2_call = native_call(__NR_openat2, AT_FDCWD_ARGUMENT, NAME_ADDRESS,
                                                   OTHER_NAME_ADDRESS, sizeof(how), 0);
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    fake_memory(OTHER_NAME_ADDRESS, &how, sizeof(how));
    check("an openat2 with a mode but no O_CREAT is silent", silent(judged(openat2_call)));
    how.flags = O_WRONLY | O_CREAT;
    how.mode = 010644;
    fake_string(NAME_ADDRESS, in_tree("ro/new"));
    fake_memory(OTHER_NAME_ADDRESS, &how, sizeof(how));
    check("and one with a mode bit outside 07777", silent(judged(openat2_call)));
    how.mode = 0644;
    fake_memory(OTHER_NAME_ADDRESS, &how, sizeof(how));
    check("while a creating one with a plain mode is judged",
          strcmp(judged(openat2_call), line_for("create", "File", in_tree("ro/new"))) == 0);
    check("a rename of a link to a directory, named with a trailing slash, is silent",
          silent(judged_two_names(&judge_model, __NR_renameat2, in_tree("rolink/"),
                                  in_tree("rw/x"), 0)));
    check("a device Landlock refuses to read is a line",
          strcmp(judged_open("/dev/null", O_RDONLY), line_for("read", "File", "/dev/null")) == 0);
    snprintf(fake_nodev_mount, sizeof(fake_nodev_mount), "/dev");
    check("but not on a nodev mount", silent(judged_open("/dev/null", O_RDONLY)));
    fake_nodev_mount[0] = '\0';
    snprintf(fake_append_only, sizeof(fake_append_only), "%s", in_tree("ro/file"));
    check("a write of an append-only file without O_APPEND is silent",
          silent(judged_open(in_tree("ro/file"), O_WRONLY)));
    check("and a truncation of it", silent(judged_open(in_tree("ro/file"), O_RDONLY | O_TRUNC)));
    fake_string(NAME_ADDRESS, in_tree("ro/file"));
    check("and a truncate of it",
          silent(judged(native_call(__NR_truncate, NAME_ADDRESS, 0, 0, 0, 0))));
    check("while an appending write of it is judged",
          strcmp(judged_open(in_tree("ro/file"), O_WRONLY | O_APPEND),
                 line_for("write", "File", in_tree("ro/file"))) == 0);
    fake_append_only[0] = '\0';
    fake_statx_fails = true;
    check("a write whose attributes cannot be told is silent",
          silent(judged_open(in_tree("ro/file"), O_WRONLY)));
    check("while a read needs no attributes and is judged",
          !silent(judged_open(in_tree("none/secret"), O_RDONLY)));
    fake_statx_fails = false;
}

static void test_judging_sticky_directories(void) {
    printf("\nAn O_CREAT open of a file another user owns in a sticky directory\n");
    reset_fakes();
    char sticky_file[] = "/tmp/phobos-sticky-XXXXXX";
    int descriptor = mkstemp(sticky_file);
    struct stat directory;
    if (descriptor < 0 || stat("/tmp", &directory) != 0 || (directory.st_mode & S_ISVTX) == 0
        || (directory.st_mode & S_IWOTH) == 0) {
        perror("a file in a sticky /tmp");
        exit(2);
    }
    close(descriptor);
    if (__real_geteuid() == 0) {
        if (chown(sticky_file, FAKE_CHILD_PID, FAKE_CHILD_PID) != 0) {
            perror("chown");
            exit(2);
        }
    } else {
        fake_euid_set = true;
        fake_euid = FAKE_CHILD_PID;
    }
    check("the kernel's protection ends it before Landlock, so it is silent",
          silent(judged_open(sticky_file, O_WRONLY | O_CREAT)));
    check("while the same open without O_CREAT is judged",
          strcmp(judged_open(sticky_file, O_WRONLY), line_for("write", "File", sticky_file)) == 0);
    check("as is an O_CREAT open of a file in a directory that is not sticky",
          strcmp(judged_open(in_tree("ro/file"), O_WRONLY | O_CREAT),
                 line_for("write", "File", in_tree("ro/file"))) == 0);
    unlink(sticky_file);
    reset_fakes();
    char sticky_link[] = "/tmp/phobos-sticky-link-XXXXXX";
    if (mkdtemp(sticky_link) == NULL || rmdir(sticky_link) != 0
        || symlink(in_tree("none/secret"), sticky_link) != 0) {
        perror("a link in a sticky /tmp");
        exit(2);
    }
    if (__real_geteuid() == 0 && lchown(sticky_link, FAKE_CHILD_PID, FAKE_CHILD_PID) != 0) {
        perror("lchown");
        exit(2);
    }
    fake_euid_set = true;
    fake_euid = __real_geteuid() == 0 ? FAKE_CHILD_PID : __real_geteuid();
    check("a link the task owns in a sticky directory is followed",
          strstr(judged_open(sticky_link, O_RDONLY), "' (named as '") != NULL);
    fake_euid = FAKE_CHILD_PID + 1;
    check("one owned by neither the task nor the directory's owner is not, so it is silent",
          silent(judged_open(sticky_link, O_RDONLY)));
    unlink(sticky_link);
    reset_fakes();
}

/* A bind of a UNIX socket on descriptor 3 to a path name. */
static const char *judged_unix_bind(const char *path, size_t length) {
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    fake_memory(NAME_ADDRESS, &address, sizeof(address));
    return judged(native_call(__NR_bind, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, length, 0, 0));
}

static constexpr char UNIX_TABLE[] =
    "Num       RefCount Protocol Flags    Type St Inode Path\n"
    "0000000000000000: 00000002 00000000 00010000 0001 01 12 /run/other\n"
    "0000000000000000: 00000002 00000000 00000000 0001 01 777\n";

static void test_judging_unix_binds(void) {
    printf("\nA bind of a UNIX socket to a path\n");
    reset_fakes();
    fake_readlink("/proc/42/fd/3", "socket:[777]");
    fake_unix_table = UNIX_TABLE;
    check("a refused bind names the socket file",
          strcmp(judged_unix_bind(in_tree("ro/sock"), sizeof(struct sockaddr_un)),
                 line_for("create", "Socket File", in_tree("ro/sock"))) == 0);
    check("a granted bind is silent",
          silent(judged_unix_bind(in_tree("rw/sock"), sizeof(struct sockaddr_un))));
    check("an existing name is silent",
          silent(judged_unix_bind(in_tree("ro/file"), sizeof(struct sockaddr_un))));
    check("an automatic name is silent", silent(judged_unix_bind("", sizeof(sa_family_t))));
    check("an abstract name is silent", silent(judged_unix_bind("", sizeof(struct sockaddr_un))));
    check("a name longer than the address allows is silent",
          silent(judged_unix_bind(in_tree("ro/sock"), sizeof(struct sockaddr_un) + 1)));
    check("an address too short to name a family is silent",
          silent(judged_unix_bind(in_tree("ro/sock"), 1)));
    check("a name with a trailing slash is silent",
          silent(judged_unix_bind(in_tree("ro/sock/"), sizeof(struct sockaddr_un))));
    fake_readlink("/proc/42/fd/3", "socket:[778]");
    check("a socket that is not a UNIX one is silent",
          silent(judged_unix_bind(in_tree("ro/sock"), sizeof(struct sockaddr_un))));
    fake_readlink("/proc/42/fd/3", "pipe:[12]");
    check("a descriptor that is no socket is silent",
          silent(judged_unix_bind(in_tree("ro/sock"), sizeof(struct sockaddr_un))));
    fake_link_count = 0;
    fake_readlink("/proc/42/root", "/");
    check("a descriptor whose link cannot be read is silent",
          silent(judged_unix_bind(in_tree("ro/sock"), sizeof(struct sockaddr_un))));
    fake_readlink("/proc/42/fd/3", "socket:[777]");
    fake_unix_table = NULL;
    check("a socket table that cannot be read is silent",
          silent(judged_unix_bind(in_tree("ro/sock"), sizeof(struct sockaddr_un))));
    fake_unix_table = UNIX_TABLE;
    fake_string(NAME_ADDRESS, "x");
    check("an address that cannot be read whole is silent",
          silent(judged(native_call(__NR_bind, DIRECTORY_DESCRIPTOR, 0x900000,
                                    sizeof(struct sockaddr_un), 0, 0))));
    struct sockaddr_in inet = {.sin_family = AF_INET, .sin_port = htons(8080)};
    fake_memory(NAME_ADDRESS, &inet, sizeof(inet));
    check("a port is not the filesystem's to judge",
          silent(judged(native_call(__NR_bind, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, sizeof(inet), 0,
                                    0))));
    fake_string(NAME_ADDRESS, "relative.sock");
    fake_readlink("/proc/42/cwd", in_tree("none"));
    struct sockaddr_un relative = {.sun_family = AF_UNIX, .sun_path = "relative.sock"};
    fake_memory(NAME_ADDRESS, &relative, sizeof(relative));
    check("a relative name is made absolute against the working directory",
          strcmp(judged(native_call(__NR_bind, DIRECTORY_DESCRIPTOR, NAME_ADDRESS,
                                    sizeof(relative), 0, 0)),
                 line_for("create", "Socket File", in_tree("none/relative.sock"))) == 0);
    fake_link_count = 0;
    fake_readlink("/proc/42/root", "/");
    fake_readlink("/proc/42/fd/3", "socket:[777]");
    check("a relative name with no readable working directory is silent",
          silent(judged(native_call(__NR_bind, DIRECTORY_DESCRIPTOR, NAME_ADDRESS,
                                    sizeof(relative), 0, 0))));
}

/* The transport the fake socket table answers for descriptor 3, and for any other. */
static int fake_socket_type = SOCK_STREAM;

static int fake_socket_type_of(pid_t pid, int descriptor) {
    return pid == FAKE_PID && descriptor == DIRECTORY_DESCRIPTOR ? fake_socket_type : -1;
}

static const char *judged_port_bind(const struct policy_model *network, const void *address,
                                    size_t length, socket_type_lookup lookup) {
    struct access_request request;
    struct task_view task = fake_task(task_status);
    fake_memory(NAME_ADDRESS, address, length);
    struct seccomp_data data = native_call(__NR_bind, DIRECTORY_DESCRIPTOR, NAME_ADDRESS, length,
                                           0, 0);
    decode_trapped_call(&data, &request);
    reset_report_for_tests();
    capture_stderr_begin();
    judge_bind_port(&task, &request, network, lookup);
    return capture_stderr_end();
}

static void test_judging_port_binds(void) {
    printf("\nA bind to a port\n");
    reset_fakes();
    static struct policy_model network;
    char *arguments[] = {"enforcer", "--no-filesystem", "--close-bind", "--bind-tcp", "8080",
                         "--", "/bin/true", NULL};
    char error[256];
    check("the network model is built", build_policy_model(7, arguments, 10, &network, error,
                                                           sizeof(error)));
    struct sockaddr_in refused_port = {.sin_family = AF_INET, .sin_port = htons(8081)};
    struct sockaddr_in granted_port = {.sin_family = AF_INET, .sin_port = htons(8080)};
    struct sockaddr_in6 refused_six = {.sin6_family = AF_INET6, .sin6_port = htons(8081)};
    fake_socket_type = SOCK_STREAM;
    check("a refused TCP port is a line for the network layer",
          strcmp(judged_port_bind(&network, &refused_port, sizeof(refused_port),
                                  fake_socket_type_of),
                 "Phobos Security Error: the program tried to illegally bind the Port 8081 over "
                 "TCP but was blocked by Phobos.\n")
              == 0);
    check("a granted TCP port is silent",
          silent(judged_port_bind(&network, &granted_port, sizeof(granted_port),
                                  fake_socket_type_of)));
    fake_socket_type = SOCK_DGRAM;
    check("a refused UDP port over IPv6 is a line",
          strcmp(judged_port_bind(&network, &refused_six, sizeof(refused_six), fake_socket_type_of),
                 "Phobos Security Error: the program tried to illegally bind the Port 8081 over "
                 "UDP but was blocked by Phobos.\n")
              == 0);
    fake_socket_type = SOCK_RAW;
    check("a socket of another type is silent",
          silent(judged_port_bind(&network, &refused_port, sizeof(refused_port),
                                  fake_socket_type_of)));
    fake_socket_type = SOCK_STREAM;
    check("without a socket table nothing is judged",
          silent(judged_port_bind(&network, &refused_port, sizeof(refused_port), NULL)));
    check("an IPv4 address too short is silent",
          silent(judged_port_bind(&network, &refused_port, sizeof(sa_family_t) + 2,
                                  fake_socket_type_of)));
    check("an IPv6 address too short is silent",
          silent(judged_port_bind(&network, &refused_six, sizeof(struct sockaddr_in),
                                  fake_socket_type_of)));
    struct sockaddr_un unix_address = {.sun_family = AF_UNIX};
    check("a UNIX address is silent",
          silent(judged_port_bind(&network, &unix_address, sizeof(unix_address),
                                  fake_socket_type_of)));
    struct access_request request;
    struct seccomp_data openat = native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, 0, 0, 0);
    decode_trapped_call(&openat, &request);
    struct task_view task = fake_task(task_status);
    capture_stderr_begin();
    judge_bind_port(&task, &request, &network, fake_socket_type_of);
    check("a call that is no bind is silent", silent(capture_stderr_end()));
}

/* ------------------------------------------------------------- arming and membership */

/* The seccomp filters a fake task carries: the enforcer at its restriction, and one more for the
 * tasks it starts, which carry the marker. */
static constexpr int ARMED_FILTERS = 3;
static constexpr int MARKED_FILTERS = ARMED_FILTERS + 1;

/* A copy of the supervisor's own status whose Seccomp_filters line says count, so the credentials
 * still match. A negative count leaves the line out. */
static const char *status_with_filters(int count) {
    static char texts[2][1 << 14];
    static size_t next = 0;
    char *text = texts[next];
    next = (next + 1) % 2;
    size_t used = 0;
    char *state = NULL;
    static char copy[1 << 14];
    snprintf(copy, sizeof(copy), "%s", task_status);
    for (char *line = strtok_r(copy, "\n", &state); line != NULL; line = strtok_r(NULL, "\n", &state)) {
        if (strncmp(line, "Seccomp_filters:", strlen("Seccomp_filters:")) != 0) {
            used += (size_t)snprintf(text + used, sizeof(texts[0]) - used, "%s\n", line);
        }
    }
    if (count >= 0) {
        snprintf(text + used, sizeof(texts[0]) - used, "Seccomp_filters:\t%d\n", count);
    }
    return text;
}

/* Fakes the command line of /proc/42 as the given words, each ended by a NUL. */
static void fake_cmdline(const char *const *words) {
    static char bytes[1 << 20];
    size_t length = 0;
    for (size_t index = 0; words[index] != NULL; index++) {
        size_t word = strlen(words[index]) + 1;
        memcpy(bytes + length, words[index], word);
        length += word;
    }
    fake_small_file("/proc/42/cmdline", bytes, length);
}

/* A notification of one native call from the fake task. */
static struct seccomp_notif notification_of(struct seccomp_data data) {
    struct seccomp_notif request;
    memset(&request, 0, sizeof(request));
    request.id = FAKE_NOTIFICATION_ID;
    request.pid = FAKE_PID;
    request.data = data;
    return request;
}

/* Services one notification and answers what was printed meanwhile. */
static const char *serviced(struct seccomp_data data) {
    struct seccomp_notif request = notification_of(data);
    struct seccomp_notif_resp response;
    capture_stderr_begin();
    reporter_service(FAKE_NOTIFY_DESCRIPTOR, &request, &response);
    return capture_stderr_end();
}

/* The enforcer's path as the reporter is configured with it, and as /proc/42/exe names it. */
static const char *enforcer(void) {
    return in_tree("ro/exe");
}

/* Lets the fake task call landlock_restrict_self as the enforcer, with the given command line and
 * filter count, and answers what was printed. */
static const char *arm_with(const char *const *words, int filters) {
    fake_readlink("/proc/42/exe", enforcer());
    fake_cmdline(words);
    fake_small_file("/proc/42/status", status_with_filters(filters),
                    strlen(status_with_filters(filters)));
    return serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0));
}

/* Makes the fake task one carrying the given number of filters, for the next observation. */
static void fake_filters(int filters) {
    const char *status = status_with_filters(filters);
    fake_small_file("/proc/42/status", status, strlen(status));
}

static void start_reporter(void) {
    reset_fakes();
    reset_reporter_for_tests();
    reset_report_for_tests();
    reporter_configure(enforcer(), 8);
}

static void test_arming_and_membership(void) {
    printf("\nArming on the enforcer, and the tasks of its domain\n");
    start_reporter();
    const char *filesystem_enforcer[] = {"enforcer", "--mark-reported-domain", "--rights=rx",
                                         in_tree("ro"), "--", "/bin/cat", NULL};
    check("before arming, a refused open is not judged",
          silent((fake_string(NAME_ADDRESS, in_tree("none/secret")),
                  serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                       0)))));
    check("arming prints nothing", silent(arm_with(filesystem_enforcer, ARMED_FILTERS)));
    check("and arms the filesystem model", reporter_current_state() == REPORTER_FILESYSTEM_ARMED
                                               && reporter_filesystem_rule_count() == 1);
    fake_filters(MARKED_FILTERS);
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    check("a task of the domain is judged",
          strcmp(serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                      0)),
                 line_for("read", "File", in_tree("none/secret"))) == 0);
    check("and its call is continued, with error and value 0",
          script->last_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE && script->last_response.error == 0
              && script->last_response.val == 0 && script->last_response.id == FAKE_NOTIFICATION_ID);
    fake_filters(ARMED_FILTERS);
    fake_string(NAME_ADDRESS, in_tree("none/dir"));
    check("a task beside the domain, with the count recorded at arming, is not judged",
          silent(serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                      0))));
    fake_small_file("/proc/42/status", NULL, 0);
    check("a task whose status cannot be read is not judged",
          silent(serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                      0))));
    fake_filters(MARKED_FILTERS);
    const char *copied[] = {"enforcer", "--rights=rwxmd", "/", "--", "/bin/cat", NULL};
    check("nothing re-arms once the filesystem model is armed",
          silent(arm_with(copied, ARMED_FILTERS)) && reporter_filesystem_rule_count() == 1);
    check("a call the reporter does not decode is continued all the same",
          silent(serviced(native_call(__NR_getpid, 0, 0, 0, 0, 0)))
              && script->last_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    unsigned int sent_before = script->responses_sent;
    script->sends_interrupted = 2;
    check("a CONTINUE whose send a signal interrupts is sent again until it is delivered",
          silent(serviced(native_call(__NR_getpid, 0, 0, 0, 0, 0)))
              && script->responses_sent == sent_before + 3 && script->sends_interrupted == 0);
    check("every answer of the run was CONTINUE with error and value 0",
          script->responses_sent > 0 && script->every_response_continued);
}

static void test_arming_in_order(void) {
    printf("\nThe network enforcer arms the bind model, the filesystem enforcer after it\n");
    start_reporter();
    const char *network_enforcer[] = {"enforcer", "--no-filesystem", "--close-bind",
                                      "--bind-tcp", "8080", "--", "bash", NULL};
    const char *filesystem_enforcer[] = {"enforcer", "--mark-reported-domain", "--rights=rx",
                                         in_tree("ro"), "--", "/bin/cat", NULL};
    check("the network enforcer arms", silent(arm_with(network_enforcer, ARMED_FILTERS - 1)));
    check("only the bind model", reporter_current_state() == REPORTER_NETWORK_ARMED);
    fake_filters(MARKED_FILTERS);
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    check("so a refused open is not yet judged",
          silent(serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                      0))));
    check("a second network enforcer changes nothing",
          silent(arm_with(network_enforcer, ARMED_FILTERS))
              && reporter_current_state() == REPORTER_NETWORK_ARMED);
    check("the filesystem enforcer arms after it", silent(arm_with(filesystem_enforcer,
                                                                   ARMED_FILTERS))
                                                       && reporter_current_state()
                                                              == REPORTER_FILESYSTEM_ARMED);
    fake_filters(MARKED_FILTERS);
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    check("and a refused open is judged from then on",
          strcmp(serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                      0)),
                 line_for("read", "File", in_tree("none/secret"))) == 0);
    struct sockaddr_in refused_port = {.sin_family = AF_INET, .sin_port = htons(8081)};
    fake_memory(OTHER_NAME_ADDRESS, &refused_port, sizeof(refused_port));
    struct seccomp_data bind_call = native_call(__NR_bind, DIRECTORY_DESCRIPTOR,
                                                OTHER_NAME_ADDRESS, sizeof(refused_port), 0, 0);
    check("without a socket table no bind is judged by its port", silent(serviced(bind_call)));
    reporter_use_socket_types(fake_socket_type_of);
    fake_socket_type = SOCK_STREAM;
    check("with one, a refused port is a line",
          strcmp(serviced(bind_call), "Phobos Security Error: the program tried to illegally bind "
                                      "the Port 8081 over TCP but was blocked by Phobos.\n")
              == 0);
}

static void test_arming_refusals(void) {
    printf("\nWhat does not arm, or turns reporting off\n");
    start_reporter();
    const char *filesystem_enforcer[] = {"enforcer", "--mark-reported-domain", "--rights=rx",
                                         in_tree("ro"), "--", "/bin/cat", NULL};
    fake_readlink("/proc/42/exe", "/usr/bin/python3");
    fake_cmdline(filesystem_enforcer);
    fake_filters(ARMED_FILTERS);
    check("a caller that is not the enforcer never arms",
          silent(serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0)))
              && reporter_current_state() == REPORTER_UNARMED);
    fake_link_count = 0;
    fake_readlink("/proc/42/root", "/");
    check("nor one whose executable cannot be read",
          silent(serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0)))
              && reporter_current_state() == REPORTER_UNARMED);
    reporter_configure(in_tree("ro/missing-enforcer"), 8);
    check("an enforcer path that does not resolve arms nothing",
          silent(arm_with(filesystem_enforcer, ARMED_FILTERS))
              && reporter_current_state() == REPORTER_UNARMED);
    start_reporter();
    fake_notification_valid = false;
    check("a notification that vanished arms nothing",
          silent(arm_with(filesystem_enforcer, ARMED_FILTERS))
              && reporter_current_state() == REPORTER_UNARMED);
    const char *notice = "Phobos: filesystem denial reporting is off for this run";
    start_reporter();
    const char *rejected[] = {"enforcer", "--rights=zz", in_tree("ro"), "--", "/bin/cat", NULL};
    check("a command line the parser rejects turns reporting off with one notice",
          strstr(arm_with(rejected, ARMED_FILTERS), notice) != NULL
              && reporter_current_state() == REPORTER_FILESYSTEM_ARMED);
    fake_filters(MARKED_FILTERS);
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    check("after which nothing is judged",
          silent(serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                      0))));
    start_reporter();
    const char *missing_rule[] = {"enforcer", "--mark-reported-domain", "--rights=r",
                                  in_tree("ro/gone"), "--", "/bin/cat", NULL};
    check("rules that cannot be modelled turn reporting off",
          strstr(arm_with(missing_rule, ARMED_FILTERS), "could not be read the way the enforcer "
                                                        "reads them")
              != NULL);
    start_reporter();
    const char *unmarked[] = {"enforcer", "--rights=rx", in_tree("ro"), "--", "/bin/cat", NULL};
    check("an enforcer not asked to mark its domain turns reporting off",
          strstr(arm_with(unmarked, ARMED_FILTERS), "was not asked to mark its domain") != NULL
              && reporter_current_state() == REPORTER_FILESYSTEM_ARMED);
    fake_filters(MARKED_FILTERS);
    fake_string(NAME_ADDRESS, in_tree("none/secret"));
    check("after which nothing is judged either",
          silent(serviced(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0,
                                      0))));
    start_reporter();
    const char *through_self[] = {"enforcer", "--mark-reported-domain", "--rights=r",
                                  "/proc/self/fd", "--", "/bin/cat", NULL};
    check("a rule through /proc/self, which the enforcer opened as itself, turns reporting off",
          strstr(arm_with(through_self, ARMED_FILTERS), "/proc/self or /proc/thread-self") != NULL);
    start_reporter();
    check("a status that does not count the filters turns reporting off",
          strstr(arm_with(filesystem_enforcer, -1), notice) != NULL);
    start_reporter();
    fake_readlink("/proc/42/exe", enforcer());
    fake_cmdline(filesystem_enforcer);
    fake_small_file("/proc/42/status", "Seccomp_filters:\n\nSeccomp_filters:\tmany\n",
                    strlen("Seccomp_filters:\n\nSeccomp_filters:\tmany\n"));
    check("so does one whose count is not a number",
          strstr(serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0)),
                 notice)
              != NULL);
    start_reporter();
    fake_readlink("/proc/42/exe", enforcer());
    fake_small_file("/proc/42/cmdline", NULL, 0);
    fake_filters(ARMED_FILTERS);
    check("a command line that cannot be read turns reporting off",
          strstr(serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0)),
                 notice)
              != NULL);
    start_reporter();
    fake_readlink("/proc/42/exe", enforcer());
    fake_small_file("/proc/42/cmdline", "", 0);
    fake_filters(ARMED_FILTERS);
    check("so does an empty one",
          strstr(serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0)),
                 notice)
              != NULL);
    start_reporter();
    fake_readlink("/proc/42/exe", enforcer());
    fake_small_file("/proc/42/cmdline", "enforcer", strlen("enforcer"));
    check("and one that does not end in a NUL",
          strstr(serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0)),
                 notice)
              != NULL);
    start_reporter();
    static const char *many[16400];
    for (size_t index = 0; index < 16390; index++) {
        many[index] = "x";
    }
    many[16390] = NULL;
    check("and one with more arguments than any enforcer takes",
          strstr(arm_with(many, ARMED_FILTERS), notice) != NULL);
    start_reporter();
    fake_readlink("/proc/42/exe", enforcer());
    fake_cmdline(filesystem_enforcer);
    fake_small_file("/proc/42/status", NULL, 0);
    check("and an enforcer whose status cannot be read",
          strstr(serviced(native_call(SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF, 0, 0, 0, 0, 0)),
                 notice)
              != NULL);
}

static void test_reporter_handles(void) {
    printf("\nWhich notifications are observation traps\n");
    struct seccomp_notif request = notification_of(native_call(__NR_openat, 0, 0, 0, 0, 0));
    check("a native path call is", reporter_handles(&request));
    request = notification_of(native_call(__NR_bind, 0, 0, 0, 0, 0));
    check("a bind is", reporter_handles(&request));
    request = notification_of(native_call(__NR_getpid, 0, 0, 0, 0, 0));
    check("a call outside the set is not", !reporter_handles(&request));
    request = notification_of(native_call(__NR_openat, 0, 0, 0, 0, 0));
    request.data.arch = AUDIT_ARCH_I386;
    check("a foreign ABI is not, whatever its number", !reporter_handles(&request));
}

/* --------------------------------------------------------------------- the refusals */

/* The numbers every class case iterates over, and the response a refusal must be. */
static constexpr int HIGHEST_NUMBER_TRIED = 500;

static bool refused_exactly(const struct seccomp_notif_resp *response, uint64_t id) {
    return response->id == id && response->val == 0 && response->error == -EACCES
           && response->flags == 0;
}

static struct seccomp_data foreign_call(unsigned int arch, int number) {
    struct seccomp_data data = native_call(number, 0, 0, 0, 0, 0);
    data.arch = arch;
    return data;
}

static void test_the_refusal_class(void) {
    printf("\nThe calls a Phobos filter refuses outright\n");
    const int refused[] = {__NR_setsid, __NR_setpgid, __NR_io_uring_setup, __NR_io_uring_enter,
                           __NR_io_uring_register};
    bool only_those = true;
    for (int number = 0; number <= HIGHEST_NUMBER_TRIED; number++) {
        bool expected = false;
        for (size_t index = 0; index < sizeof(refused) / sizeof(refused[0]); index++) {
            expected = expected || number == refused[index];
        }
        struct seccomp_data data = native_call(number, 0, 0, 0, 0, 0);
        only_those = only_those && is_filter_refusal(&data) == expected;
    }
    check("of the native numbers, exactly setsid, setpgid and the three io_uring calls",
          only_those);
    struct seccomp_data connect_call = native_call(__NR_connect, 0, 0, 0, 0, 0);
    check("connect is not one of them", !is_filter_refusal(&connect_call));
    bool every_foreign = true;
    for (int number = 0; number <= HIGHEST_NUMBER_TRIED; number++) {
        struct seccomp_data data = foreign_call(AUDIT_ARCH_I386, number);
        every_foreign = every_foreign && is_filter_refusal(&data);
    }
    check("every i386 number is one, decided before the number is read", every_foreign);
    struct seccomp_data foreign_connect = foreign_call(AUDIT_ARCH_I386, __NR_connect);
    check("a foreign number equal to the native connect is one", is_filter_refusal(&foreign_connect));
#ifdef __X32_SYSCALL_BIT
    struct seccomp_data x32 = native_call((int)(__X32_SYSCALL_BIT | __NR_openat), 0, 0, 0, 0, 0);
    check("an x32 number is one", is_filter_refusal(&x32));
#endif
}

/* Answers one refusal and answers what it printed. */
static const char *refusal_answered(struct seccomp_data data, enum report_layer layer) {
    struct seccomp_notif request = notification_of(data);
    struct seccomp_notif_resp response;
    capture_stderr_begin();
    answer_filter_refusal(FAKE_NOTIFY_DESCRIPTOR, &request, &response, layer);
    return capture_stderr_end();
}

static void test_answering_refusals(void) {
    printf("\nA refusal is answered with EACCES and never continued\n");
    reset_fakes();
    reset_report_for_tests();
    bool every_one_refused = true;
    const int refused[] = {__NR_setsid, __NR_setpgid, __NR_io_uring_setup, __NR_io_uring_enter,
                           __NR_io_uring_register};
    for (size_t index = 0; index < sizeof(refused) / sizeof(refused[0]); index++) {
        refusal_answered(native_call(refused[index], 0, 0, 0, 0, 0), REPORT_LAYER_TIMEOUT);
        every_one_refused = every_one_refused
                            && refused_exactly(&script->last_response, FAKE_NOTIFICATION_ID);
    }
    for (int number = 0; number <= HIGHEST_NUMBER_TRIED; number++) {
        refusal_answered(foreign_call(AUDIT_ARCH_I386, number), REPORT_LAYER_TIMEOUT);
        every_one_refused = every_one_refused
                            && refused_exactly(&script->last_response, FAKE_NOTIFICATION_ID);
    }
#ifdef __X32_SYSCALL_BIT
    for (int number = 0; number <= HIGHEST_NUMBER_TRIED; number++) {
        refusal_answered(native_call((int)(__X32_SYSCALL_BIT | (unsigned int)number), 0, 0, 0, 0,
                                     0),
                         REPORT_LAYER_TIMEOUT);
        every_one_refused = every_one_refused
                            && refused_exactly(&script->last_response, FAKE_NOTIFICATION_ID);
    }
#endif
    check("every call of the class, on both ABIs, gets error -EACCES, value 0 and flags 0",
          every_one_refused && script->responses_sent > 0);
    check("and not one of them was continued", script->last_response.flags == 0);
    unsigned int sent_before = script->responses_sent;
    script->sends_interrupted = 2;
    refusal_answered(native_call(__NR_setsid, 0, 0, 0, 0, 0), REPORT_LAYER_TIMEOUT);
    check("a refusal whose send a signal interrupts is sent again until it is delivered",
          script->responses_sent == sent_before + 3 && script->sends_interrupted == 0
              && refused_exactly(&script->last_response, FAKE_NOTIFICATION_ID));
    reset_report_for_tests();
    check("setsid leaves the Session",
          strcmp(refusal_answered(native_call(__NR_setsid, 0, 0, 0, 0, 0), REPORT_LAYER_TIMEOUT),
                 "Phobos Security Error: the program tried to illegally leave the Session but was "
                 "blocked by Phobos.\n")
              == 0);
    check("setpgid leaves the Process Group",
          strcmp(refusal_answered(native_call(__NR_setpgid, 0, 0, 0, 0, 0), REPORT_LAYER_TIMEOUT),
                 "Phobos Security Error: the program tried to illegally leave the Process Group but "
                 "was blocked by Phobos.\n")
              == 0);
    check("io_uring is a Kernel Interface",
          strcmp(refusal_answered(native_call(__NR_io_uring_setup, 0, 0, 0, 0, 0),
                                  REPORT_LAYER_NETWORK),
                 "Phobos Security Error: the program tried to illegally use the Kernel Interface "
                 "io_uring but was blocked by Phobos.\n")
              == 0);
    check("an i386 call names its ABI and its number",
          strcmp(refusal_answered(foreign_call(AUDIT_ARCH_I386, 20), REPORT_LAYER_TIMEOUT),
                 "Phobos Security Error: the program tried to illegally use the Kernel Interface "
                 "i386 system call 20 but was blocked by Phobos.\n")
              == 0);
    check("another ABI is named by its audit number",
          strstr(refusal_answered(foreign_call(AUDIT_ARCH_ARM, 7), REPORT_LAYER_TIMEOUT),
                 "use the Kernel Interface foreign ABI 0x40000028 system call 7 but") != NULL);
#ifdef __X32_SYSCALL_BIT
    check("an x32 call names its ABI and its own number",
          strstr(refusal_answered(native_call((int)(__X32_SYSCALL_BIT | 41U), 0, 0, 0, 0, 0),
                                  REPORT_LAYER_TIMEOUT),
                 "use the Kernel Interface x32 system call 41 but") != NULL);
#endif
    capture_stderr_begin();
    report_summary();
    check("the refusals are counted for the layer given",
          strstr(capture_stderr_end(), "1 in the network layer and ") != NULL);
}

/* -------------------------------------------------------------------------- the filter */

/* Runs a classic BPF program over one call, the way the kernel runs a seccomp filter, and answers
 * the action it returns. Only the instructions the filters here use are known. */
static constexpr unsigned int UNKNOWN_INSTRUCTION = 0xdeadbeef;

static unsigned int run_filter(const struct sock_filter *program, size_t length,
                               const struct seccomp_data *data) {
    uint32_t accumulator = 0;
    for (size_t counter = 0; counter < length; counter++) {
        const struct sock_filter *instruction = &program[counter];
        switch (instruction->code) {
        case BPF_LD | BPF_W | BPF_ABS:
            memcpy(&accumulator, (const char *)data + instruction->k, sizeof(accumulator));
            break;
        case BPF_JMP | BPF_JEQ | BPF_K:
            counter += accumulator == instruction->k ? instruction->jt : instruction->jf;
            break;
        case BPF_JMP | BPF_JSET | BPF_K:
            counter += (accumulator & instruction->k) != 0 ? instruction->jt : instruction->jf;
            break;
        case BPF_RET | BPF_K:
            return instruction->k;
        default:
            return UNKNOWN_INSTRUCTION;
        }
    }
    return UNKNOWN_INSTRUCTION;
}

static bool in_report_set(int number) {
    for (size_t index = 0; index < REPORT_TRAPPED_CALL_COUNT; index++) {
        if (REPORT_TRAPPED_CALLS[index] == number) {
            return true;
        }
    }
    return false;
}

/* Whether a filter traps exactly what it should, for every native number tried and a foreign ABI. */
static bool filter_traps_exactly(bool file_traps, bool refusal_traps) {
    struct sock_filter program[REPORT_FILTER_MAXIMUM];
    size_t length = build_report_filter(program, file_traps, refusal_traps);
    bool exact = true;
    for (int number = 0; number <= HIGHEST_NUMBER_TRIED; number++) {
        struct seccomp_data data = native_call(number, 0, 0, 0, 0, 0);
        bool refusal = number == __NR_setsid || number == __NR_setpgid;
        bool trapped = (file_traps && in_report_set(number)) || (refusal_traps && refusal);
        unsigned int expected = trapped ? SECCOMP_RET_USER_NOTIF : SECCOMP_RET_ALLOW;
        exact = exact && run_filter(program, length, &data) == expected;
    }
    struct seccomp_data foreign = foreign_call(AUDIT_ARCH_I386, __NR_openat);
    exact = exact && run_filter(program, length, &foreign)
                         == (refusal_traps ? SECCOMP_RET_USER_NOTIF : SECCOMP_RET_ALLOW);
#ifdef __X32_SYSCALL_BIT
    struct seccomp_data x32 = native_call((int)(__X32_SYSCALL_BIT | 1U), 0, 0, 0, 0, 0);
    exact = exact && run_filter(program, length, &x32)
                         == (refusal_traps ? SECCOMP_RET_USER_NOTIF : SECCOMP_RET_ALLOW);
#endif
    return exact;
}

static void test_the_filter(void) {
    printf("\nThe report-only supervisor's filter\n");
    check("with the observation traps alone it traps exactly the report set",
          filter_traps_exactly(true, false));
    check("with the refusal traps alone it traps exactly setsid, setpgid and foreign ABIs",
          filter_traps_exactly(false, true));
    check("with both it traps exactly the union", filter_traps_exactly(true, true));
    struct sock_filter both[REPORT_FILTER_MAXIMUM];
    size_t both_length = build_report_filter(both, true, true);
    bool every_other_trap_refused = true;
    bool no_observation_refused = true;
    const unsigned int arches[] = {REPORT_NATIVE_AUDIT_ARCH, AUDIT_ARCH_I386};
    for (size_t arch = 0; arch < sizeof(arches) / sizeof(arches[0]); arch++) {
        for (int number = 0; number <= HIGHEST_NUMBER_TRIED; number++) {
            struct seccomp_data data = foreign_call(arches[arch], number);
            bool observed = arches[arch] == REPORT_NATIVE_AUDIT_ARCH && in_report_set(number);
            if (run_filter(both, both_length, &data) == SECCOMP_RET_USER_NOTIF && !observed) {
                every_other_trap_refused = every_other_trap_refused && is_filter_refusal(&data);
            }
            no_observation_refused = no_observation_refused && !(observed && is_filter_refusal(&data));
        }
    }
    check("every call the filter traps beyond the observation traps is one the refusal handler takes",
          every_other_trap_refused);
    check("and no observation trap is one it takes", no_observation_refused);
    struct sock_filter program[REPORT_FILTER_MAXIMUM];
    check("the traps are not written into too small a room",
          append_report_traps(program, REPORT_TRAPPED_CALL_COUNT) == 0);
    check("every trap is one comparison and one answer",
          append_report_traps(program, REPORT_FILTER_MAXIMUM) == 2 * REPORT_TRAPPED_CALL_COUNT);
    struct sock_filter unknown[] = {BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0)};
    struct seccomp_data data = native_call(0, 0, 0, 0, 0, 0);
    check("the interpreter refuses an instruction it does not know, and a program with no answer",
          run_filter(unknown, 1, &data) == UNKNOWN_INSTRUCTION
              && run_filter(program, 0, &data) == UNKNOWN_INSTRUCTION);
    reset_fakes();
    reset_script();
    check("the filter is installed with a listener",
          install_report_filter(true, true) == FAKE_LISTENER && script->filters_installed == 1
              && script->installed_flags == SECCOMP_FILTER_FLAG_NEW_LISTENER);
    size_t length = build_report_filter(program, true, true);
    check("as built", script->installed_length == length
                          && memcmp(script->installed, program, length * sizeof(program[0])) == 0);
    script->active = false;
}

/* -------------------------------------------------------------------------- the probes */

/* Runs body in a real child of the suite and answers how it ended: its exit status, or 128 plus the
 * signal that ended it. */
static int ended_with(void (*body)(void)) {
    fflush(NULL);
    pid_t child = __real_fork();
    if (child == 0) {
        body();
        _exit(RETURNED_STATUS);
    }
    int status = 0;
    __real_waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static void probe_continue_in_child(void) {
    continue_supported();
}

static void probe_group_lock_in_child(void) {
    group_lock_present();
}

/* A script in which the continue probe's parent half sees everything go right. */
static void script_continue_probe(void) {
    reset_fakes();
    reset_script();
    script_forks(FAKE_CHILD_PID, 0, 0);
    script->fork_count = 1;
    script_poll(1, POLLIN, 0);
    script_notification(native_call(__NR_getppid, 0, 0, 0, 0, 0));
    script->read_value = getpid();
}

static void test_the_continue_probe(void) {
    printf("\nThe probe that proves CONTINUE\n");
    script_continue_probe();
    check("a probe whose trapped call was continued proves it", __real_continue_supported());
    check("by answering it with CONTINUE",
          script->last_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    script_continue_probe();
    script->send_fails = true;
    check("a refused CONTINUE does not", !__real_continue_supported());
    script_continue_probe();
    script->read_value = getpid() + 1;
    check("nor a probe that reports another parent", !__real_continue_supported());
    script_continue_probe();
    script->read_result = 0;
    check("nor a probe that reports nothing", !__real_continue_supported());
    script_continue_probe();
    script->polls[0].result = 0;
    script->polls[0].listener_events = 0;
    check("nor a notification that never comes", !__real_continue_supported());
    script_continue_probe();
    script->polls[0].listener_events = POLLHUP;
    check("nor a listener that hangs up", !__real_continue_supported());
    script_continue_probe();
    script->notification_count = 0;
    check("nor a notification that cannot be received", !__real_continue_supported());
    script_continue_probe();
    script->calloc_fails = true;
    check("nor a probe with no memory to answer it", !__real_continue_supported());
    script_continue_probe();
    script->receive_result = -1;
    check("nor a probe that hands no listener over", !__real_continue_supported());
    script_continue_probe();
    script->forks[0] = -1;
    check("nor a fork that fails", !__real_continue_supported());
    script_continue_probe();
    script->socketpair_fails = true;
    check("nor a socket pair that fails", !__real_continue_supported());
    script_continue_probe();
    script->forks[0] = 0;
    check("the probe child that reports ends cleanly", ended_with(probe_continue_in_child) == 0);
    script_continue_probe();
    script->forks[0] = 0;
    script->write_result = 0;
    check("one that cannot report ends with its failure status",
          ended_with(probe_continue_in_child) == PROBE_FAILED_STATUS);
    script_continue_probe();
    script->forks[0] = 0;
    script->send_result = false;
    check("as does one that cannot hand its listener over",
          ended_with(probe_continue_in_child) == PROBE_FAILED_STATUS);
    script_continue_probe();
    script->forks[0] = 0;
    script->listener_result = -1;
    script->listener_error = EBUSY;
    check("or install one", ended_with(probe_continue_in_child) == PROBE_FAILED_STATUS);
    script_continue_probe();
    script->forks[0] = 0;
    script->prctl_fails = true;
    check("or set no_new_privs", ended_with(probe_continue_in_child) == PROBE_FAILED_STATUS);
    script->active = false;
}

/* Frees a pair of notification buffers and forgets them, so a later allocation that fails leaves
 * nothing behind that could be freed a second time. */
static void release_notification_buffers(struct seccomp_notif **request,
                                         struct seccomp_notif_resp **response) {
    free(*request);
    free(*response);
    *request = NULL;
    *response = NULL;
}

static void test_notification_buffers(void) {
    printf("\nNotification buffers of the kernel's sizes\n");
    reset_fakes();
    reset_script();
    struct seccomp_notif *request = NULL;
    struct seccomp_notif_resp *response = NULL;
    size_t size = 0;
    check("a kernel's larger sizes are used",
          allocate_notification_buffers(&request, &size, &response)
              && size == sizeof(struct seccomp_notif) + 16);
    release_notification_buffers(&request, &response);
    script->notif_sizes_small = true;
    check("never less than this build's structures",
          allocate_notification_buffers(&request, &size, &response)
              && size == sizeof(struct seccomp_notif));
    release_notification_buffers(&request, &response);
    script->notif_sizes_small = false;
    script->notif_sizes_fail = true;
    check("and this build's sizes when the kernel does not say",
          allocate_notification_buffers(&request, &size, &response)
              && size == sizeof(struct seccomp_notif));
    release_notification_buffers(&request, &response);
    script->calloc_fails = true;
    check("no memory leaves neither allocated",
          !allocate_notification_buffers(&request, &size, &response) && request == NULL
              && response == NULL);
    script->active = false;
}

static void test_the_group_lock_probe(void) {
    printf("\nThe probe that finds the group lock's signature\n");
    reset_fakes();
    reset_script();
    script_forks(FAKE_CHILD_PID, 0, 0);
    script->fork_count = 1;
    script->wait_status = SIGNATURE_SEEN_STATUS << 8;
    check("a probe that saw the signature finds the lock", __real_group_lock_present());
    reset_script();
    script_forks(FAKE_CHILD_PID, 0, 0);
    script->fork_count = 1;
    script->wait_status = 1 << 8;
    check("one that did not, does not", !__real_group_lock_present());
    reset_script();
    script_forks(FAKE_CHILD_PID, 0, 0);
    script->fork_count = 1;
    script->wait_status = SIGKILL;
    check("nor one that was killed", !__real_group_lock_present());
    reset_script();
    script_forks(FAKE_CHILD_PID, 0, 0);
    script->fork_count = 1;
    script->wait_fails = true;
    check("nor one whose status could not be read, which is never taken for a sighting",
          !__real_group_lock_present());
    reset_script();
    script_forks(-1, 0, 0);
    script->fork_count = 1;
    check("nor a fork that fails", !__real_group_lock_present());
    reset_script();
    script_forks(0, 0, 0);
    script->fork_count = 1;
    script->setpgid_error = ENOTRECOVERABLE;
    check("the probe child reports ENOTRECOVERABLE as the signature",
          ended_with(probe_group_lock_in_child) == SIGNATURE_SEEN_STATUS);
    reset_script();
    script_forks(0, 0, 0);
    script->fork_count = 1;
    script->setpgid_error = EINVAL;
    check("and the kernel's own EINVAL as its absence", ended_with(probe_group_lock_in_child) == 1);
    reset_script();
    script_forks(0, 0, 0);
    script->fork_count = 1;
    script->setpgid_result = 0;
    script->setpgid_error = ENOTRECOVERABLE;
    check("and a call that went through as its absence too",
          ended_with(probe_group_lock_in_child) == 1);
    script->active = false;
}

/* ----------------------------------------------------------------- the supervisor's stages */

/* The arguments the next supervisor run is given, and how many there are. */
static char *supervisor_arguments[16];
static int supervisor_argument_count = 0;

static void run_supervisor(void) {
    _exit(sut_main(supervisor_argument_count, supervisor_arguments));
}

/* Runs the supervisor with the given arguments in a real child, and answers how it ended; what it
 * printed is in captured_text. */
static int supervisor_ended_with(const char *const *words) {
    supervisor_argument_count = 0;
    for (; words[supervisor_argument_count] != NULL; supervisor_argument_count++) {
        supervisor_arguments[supervisor_argument_count] = (char *)words[supervisor_argument_count];
    }
    supervisor_arguments[supervisor_argument_count] = NULL;
    capture_stderr_begin();
    int status = ended_with(run_supervisor);
    capture_stderr_end();
    return status;
}

/* A script for one run with everything available: Landlock 8, CONTINUE proved, no group lock, a
 * fork into the parent, and a listener that arrives. */
static void script_supervisor(void) {
    reset_fakes();
    reset_script();
    reset_report_for_tests();
    reset_reporter_for_tests();
    script->landlock_version_faked = true;
    script->fake_landlock_version = 8;
    script->fake_continue = 1;
    script->fake_group_lock = 0;
    script->reap_faked = true;
    script_forks(FAKE_CHILD_PID, FAKE_CHILD_PID, FAKE_CHILD_PID);
}

static void test_supervisor_usage(void) {
    printf("\nThe supervisor's command line\n");
    script_supervisor();
    const char *nothing[] = {"phobos-seccomp-filesystem", NULL};
    check("no arguments are a usage error", supervisor_ended_with(nothing) == EXIT_CODE_USAGE
                                                && strstr(captured_text, "Usage:") != NULL);
    const char *unknown[] = {"phobos-seccomp-filesystem", "--nonsense", "--", "true", NULL};
    check("an unknown option is one", supervisor_ended_with(unknown) == EXIT_CODE_USAGE);
    const char *dangling[] = {"phobos-seccomp-filesystem", "--landlock-bin", NULL};
    check("--landlock-bin with no value is one", supervisor_ended_with(dangling) == EXIT_CODE_USAGE);
    const char *no_command[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true", "--",
                                NULL};
    check("nothing to run is one", supervisor_ended_with(no_command) == EXIT_CODE_USAGE);
    const char *no_enforcer[] = {"phobos-seccomp-filesystem", "--", "true", NULL};
    check("no --landlock-bin is one", supervisor_ended_with(no_enforcer) == EXIT_CODE_USAGE);
    script->active = false;
}

static void test_supervisor_with_nothing_to_watch(void) {
    printf("\nA supervisor with nothing to watch execs the command\n");
    const char *no_landlock[] = {"phobos-seccomp-filesystem", "--verbose", "--landlock-bin",
                                 "/bin/true", "--no-landlock", "--", "/bin/true", NULL};
    script_supervisor();
    check("without Landlock to report and no group lock above, the command runs unsupervised",
          supervisor_ended_with(no_landlock) == EXIT_CODE_STAND_IN && script->executions == 1
              && script->fork_next == 0 && script->filters_installed == 0
              && strstr(captured_text, "nothing to watch") != NULL);
    const char *watch[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true", "--",
                           "/bin/true", NULL};
    script_supervisor();
    script->fake_landlock_version = 0;
    check("a kernel without Landlock is said once",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->filters_installed == 0
              && strstr(captured_text, "Phobos: filesystem denial reporting is off for this run, "
                                       "because this kernel has no Landlock")
                     != NULL);
    script_supervisor();
    script->fake_continue = 0;
    check("so is a kernel that cannot continue a supervised call",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->filters_installed == 0
              && strstr(captured_text, "Phobos: filesystem denial reporting is off for this run, "
                                       "because this kernel cannot continue a supervised call")
                     != NULL);
    const char *lock_above[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true",
                                "--no-landlock", "--group-lock-above", "--", "/bin/true", NULL};
    script_supervisor();
    check("a group lock the layers name but whose signature is missing is said, and not trapped",
          supervisor_ended_with(lock_above) == EXIT_CODE_STAND_IN && script->filters_installed == 0
              && strstr(captured_text, "its signature was not found") != NULL);
    const char *missing[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true",
                             "--no-landlock", "--", "/no/such/program", NULL};
    script_supervisor();
    check("a command that cannot be executed ends with 127",
          supervisor_ended_with(missing) == EXIT_CODE_COMMAND_NOT_EXECUTABLE);
    script->active = false;
}

static void test_supervisor_child(void) {
    printf("\nThe supervisor's child installs the filter and becomes the command\n");
    const char *watch[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true", "--",
                           "/bin/true", NULL};
    script_supervisor();
    script->forks[0] = 0;
    check("it installs one filter with a listener, hands it up and execs the command",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->filters_installed == 1
              && script->installed_flags == SECCOMP_FILTER_FLAG_NEW_LISTENER
              && strcmp(script->executed, "/bin/true") == 0);
    struct sock_filter observation_only[REPORT_FILTER_MAXIMUM];
    size_t length = build_report_filter(observation_only, true, false);
    check("with the observation traps and no refusal trap when there is no group lock",
          script->installed_length == length
              && memcmp(script->installed, observation_only, length * sizeof(observation_only[0]))
                     == 0);
    const char *both[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true",
                          "--group-lock-above", "--", "/bin/true", NULL};
    script_supervisor();
    script->forks[0] = 0;
    script->fake_group_lock = 1;
    struct sock_filter with_refusals[REPORT_FILTER_MAXIMUM];
    length = build_report_filter(with_refusals, true, true);
    check("with both kinds when the layers and the signature agree on the group lock",
          supervisor_ended_with(both) == EXIT_CODE_STAND_IN && script->installed_length == length
              && memcmp(script->installed, with_refusals, length * sizeof(with_refusals[0])) == 0);
    script_supervisor();
    script->forks[0] = 0;
    script->fake_group_lock = 1;
    script->fake_landlock_version = 0;
    length = build_report_filter(with_refusals, false, true);
    check("and the refusal traps alone when Landlock is missing",
          supervisor_ended_with(both) == EXIT_CODE_STAND_IN && script->installed_length == length
              && memcmp(script->installed, with_refusals, length * sizeof(with_refusals[0])) == 0);
    script_supervisor();
    script->forks[0] = 0;
    script->listener_result = -1;
    script->listener_error = EBUSY;
    check("a listener held above it is said once, and the command runs unsupervised",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->executions == 1
              && strstr(captured_text, "Phobos: filesystem denial reporting is off for this run, "
                                       "because another supervisor already holds the run's "
                                       "listener")
                     != NULL
              && strstr(captured_text, "group lock") == NULL);
    const char *lock_only[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true",
                               "--no-landlock", "--group-lock-above", "--", "/bin/true", NULL};
    script_supervisor();
    script->forks[0] = 0;
    script->fake_group_lock = 1;
    script->listener_result = -1;
    script->listener_error = EBUSY;
    check("when only the group lock's refusals were to be reported, the notice names only them",
          supervisor_ended_with(lock_only) == EXIT_CODE_STAND_IN
              && strstr(captured_text, "Phobos: the group lock's refusals are not reported in this "
                                       "run, because another supervisor already holds")
                     != NULL
              && strstr(captured_text, "filesystem denial") == NULL);
    script_supervisor();
    script->forks[0] = 0;
    script->fake_group_lock = 1;
    script->fake_landlock_version = 0;
    script->listener_result = -1;
    script->listener_error = EBUSY;
    check("without Landlock and with no filter, each notice names only its own subject",
          supervisor_ended_with(both) == EXIT_CODE_STAND_IN
              && count_occurrences(captured_text, "Phobos: filesystem denial reporting is off for "
                                                  "this run, because this kernel has no Landlock")
                     == 1
              && count_occurrences(captured_text, "Phobos: the group lock's refusals are not "
                                                  "reported in this run, because another "
                                                  "supervisor")
                     == 1
              && strstr(captured_text, "filesystem denials and") == NULL);
    script_supervisor();
    script->forks[0] = 0;
    script->fake_group_lock = 1;
    script->listener_result = -1;
    script->listener_error = EBUSY;
    check("and when both were to be reported, it names both",
          supervisor_ended_with(both) == EXIT_CODE_STAND_IN
              && strstr(captured_text, "Phobos: filesystem denials and the group lock's refusals "
                                       "are not reported in this run, because another supervisor")
                     != NULL);
    script_supervisor();
    script->forks[0] = 0;
    script->listener_result = -1;
    script->listener_error = EINVAL;
    check("so is any other filter that cannot be installed",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN
              && strstr(captured_text, "its seccomp filter could not be installed") != NULL);
    script_supervisor();
    script->forks[0] = 0;
    script->prctl_fails = true;
    check("and no_new_privs that cannot be set",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->filters_installed == 0
              && strstr(captured_text, "its seccomp filter could not be installed") != NULL);
    script_supervisor();
    script->forks[0] = 0;
    script->send_result = false;
    check("a listener that cannot be handed up ends the child, whose calls would all fail",
          supervisor_ended_with(watch) == EXIT_CODE_RUNTIME && script->executions == 0);
    script->active = false;
}

static void test_supervisor_parent(void) {
    printf("\nThe supervisor answers until its child has ended\n");
    const char *watch[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true",
                           "--group-lock-above", "--", "/bin/true", NULL};
    script_supervisor();
    script->fake_group_lock = 1;
    script->reaped_status = 7 << 8;
    script_notification(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0, 0));
    script_notification(native_call(__NR_setsid, 0, 0, 0, 0, 0));
    script_poll(-1, 0, 0);
    script->polls[0].error = EINTR;
    script_poll(1, POLLIN, 0);
    script_poll(1, POLLIN, 0);
    script_poll(1, 0, POLLIN);
    check("it ends with its child's status",
          supervisor_ended_with(watch) == 7 && script->notification_next == 2);
    check("having continued the observation trap and refused the refusal trap",
          script->responses_sent == 2 && refused_exactly(&script->last_response,
                                                         FAKE_NOTIFICATION_ID + 1));
    check("and reported the refusal", strstr(captured_text, "leave the Session") != NULL);
    check("and handed what is left to a drainer", script->fork_next == 2);
    script_supervisor();
    script->reaped_status = 3 << 8;
    script_poll(1, POLLHUP, 0);
    check("when no task is left it starts no drainer",
          supervisor_ended_with(watch) == 3 && script->fork_next == 1);
    script_supervisor();
    script_poll(1, POLLIN, 0);
    script_poll(1, POLLHUP, 0);
    check("a notification that vanished before it was received is answered by nobody",
          supervisor_ended_with(watch) == 0 && script->responses_sent == 0);
    script_supervisor();
    script_poll(-1, 0, 0);
    check("a poll that fails ends the supervision like a hangup",
          supervisor_ended_with(watch) == 0 && script->fork_next == 1);
    script_supervisor();
    script->pidfd_result = -1;
    script_poll(1, POLLIN | POLLHUP, 0);
    script_notification(native_call(__NR_getpid, 0, 0, 0, 0, 0));
    check("without a process descriptor it answers until no task is left",
          supervisor_ended_with(watch) == 0 && script->responses_sent == 1);
    script_supervisor();
    script->set_flags_fails = true;
    script_poll(1, POLLHUP, 0);
    check("a kernel without synchronous wake-up is said once",
          supervisor_ended_with(watch) == 0
              && strstr(captured_text, "cannot wake the reporter synchronously") != NULL);
    script_supervisor();
    script->receive_result = -1;
    script->reaped_status = 9 << 8;
    check("a child that ran without a filter is waited for and its status kept",
          supervisor_ended_with(watch) == 9 && script->responses_sent == 0);
    script_supervisor();
    script->receive_result = -1;
    script->reaped_status = 0;
    script->reap_unread = true;
    check("a status that cannot be read ends the run with PHB-ESTATUS, never with 0",
          supervisor_ended_with(watch) == EXIT_CODE_STATUS_UNREAD
              && strstr(captured_text, "exit status could not be read") != NULL);
    script_supervisor();
    script->receive_result = -1;
    check("the supervisor takes SIGCHLD's default before anything forks, and keeps it itself",
          supervisor_ended_with(watch) == 0 && script->child_signal_taken == 1
              && script->child_signal_restored == 0);
    script_supervisor();
    script->forks[0] = 0;
    check("and its child gives back the disposition it inherited before it becomes the command",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->child_signal_taken == 1
              && script->child_signal_restored == 1);
    script_supervisor();
    script->fake_landlock_version = 0;
    check("as does a supervisor that has nothing to watch and becomes the command at once",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->child_signal_taken == 1
              && script->child_signal_restored == 1);
    script_supervisor();
    script->calloc_fails = true;
    check("no memory for notifications is said before anything is forked, and the command runs "
          "unsupervised",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->fork_next == 0
              && script->filters_installed == 0
              && strstr(captured_text, "no memory to answer notifications") != NULL);
    const char *refusals_only[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true",
                                   "--no-landlock", "--group-lock-above", "--", "/bin/true", NULL};
    script_supervisor();
    script->fake_group_lock = 1;
    script->calloc_fails = true;
    check("which, when only the group lock's refusals were to be reported, names only them",
          supervisor_ended_with(refusals_only) == EXIT_CODE_STAND_IN
              && strstr(captured_text, "the group lock's refusals are not reported in this run, "
                                       "because there is no memory")
                     != NULL
              && strstr(captured_text, "filesystem denial") == NULL);
    script_supervisor();
    script->socketpair_fails = true;
    check("so is a socket pair that cannot be made",
          supervisor_ended_with(watch) == EXIT_CODE_STAND_IN && script->fork_next == 0
              && strstr(captured_text, "no socket pair could be made") != NULL);
    script_supervisor();
    script->forks[0] = -1;
    check("a fork that fails ends the run with PHB-ERUNTIME",
          supervisor_ended_with(watch) == EXIT_CODE_RUNTIME);
    script->active = false;
}

static void test_the_drainer(void) {
    printf("\nThe drainer answers what the child left behind\n");
    const char *watch[] = {"phobos-seccomp-filesystem", "--landlock-bin", "/bin/true", "--",
                           "/bin/true", NULL};
    script_supervisor();
    script->forks[1] = 0;
    script_poll(1, 0, POLLIN);
    script_poll(1, POLLIN, 0);
    script_poll(1, POLLHUP, 0);
    script_notification(native_call(__NR_openat, AT_FDCWD_ARGUMENT, NAME_ADDRESS, O_RDONLY, 0, 0));
    check("it answers until no task is left and ends cleanly",
          supervisor_ended_with(watch) == 0 && script->responses_sent == 1
              && script->every_response_continued);
    script->active = false;
}

int main(int argument_count, char *arguments[]) {
    if (argument_count == 3 && strcmp(arguments[1], "--quote") == 0) {
        static char out[REPORT_QUOTED_MAXIMUM];
        quote_like_bash(arguments[2], out, sizeof(out));
        fputs(out, stdout);
        return 0;
    }
    script = mmap(NULL, sizeof(*script), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (script == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    memset(script, 0, sizeof(*script));
    printf("denial reporter unit tests\n");
    test_quoting_matches_bash();
    test_a_long_path_is_cut();
    test_a_line_is_byte_exact();
    test_named_path_and_truncation();
    test_repeats_are_counted_not_printed();
    test_summary_singulars_and_silence();
    test_the_cap_holds();
    test_a_full_table_still_counts();
    test_the_model_links_without_diagnostics();
    test_decode_the_at_calls();
#ifdef __NR_open
    test_decode_the_legacy_calls();
#endif
    test_decode_refuses_what_it_does_not_know();
    test_report_set_is_disjoint();
    build_tree();
    build_narrow_model();
    __real_read_small_file("/proc/self/status", task_status, sizeof(task_status), NULL);
    test_reading_names();
    test_resolving_names();
    test_walking_names_as_the_task();
    test_reading_strings();
    test_reading_small_files();
    test_judging_opens();
    test_opens_that_stay_silent();
    test_tasks_that_are_not_judged();
    test_judging_openat2();
    test_judging_execution();
    test_judging_creation();
    test_judging_removal();
    test_judging_renames();
    test_judging_links();
    test_judging_truncation();
    test_judging_as_the_task();
    test_judging_what_the_kernel_checks_first();
    test_judging_sticky_directories();
    test_judging_unix_binds();
    test_judging_port_binds();
    test_arming_and_membership();
    test_arming_in_order();
    test_arming_refusals();
    test_reporter_handles();
    test_the_refusal_class();
    test_answering_refusals();
    test_the_filter();
    test_the_continue_probe();
    test_notification_buffers();
    test_the_group_lock_probe();
    test_supervisor_usage();
    test_supervisor_with_nothing_to_watch();
    test_supervisor_child();
    test_supervisor_parent();
    test_the_drainer();
    remove_tree();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
