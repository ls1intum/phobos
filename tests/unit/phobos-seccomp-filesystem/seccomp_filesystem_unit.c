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

/* The command's /proc links. A link under /proc/42 that is not here does not exist. */
static constexpr size_t FAKE_LINK_COUNT = 16;
struct fake_link {
    char path[64];
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

/* Whether the notification is still pending, and every answer sent on the listener. */
static bool fake_notification_valid = true;
static unsigned int responses_sent = 0;
static struct seccomp_notif_resp last_response;
static bool every_response_continued = true;

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
    if (request == SECCOMP_IOCTL_NOTIF_SEND) {
        memcpy(&last_response, argument, sizeof(last_response));
        responses_sent++;
        every_response_continued = every_response_continued
                                   && last_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE
                                   && last_response.error == 0 && last_response.val == 0;
        return 0;
    }
    return __real_ioctl(descriptor, request, argument);
}

/* A path the file mode refuses, a mount that is read-only or noexec, a mount that differs, a
 * statx that fails. Empty means none. */
static char fake_refused_access[PATH_MAX];
static char fake_read_only_mount[PATH_MAX];
static char fake_noexec_mount[PATH_MAX];
static char fake_other_mount[PATH_MAX];
static bool fake_statx_fails = false;

static bool beneath_or_at(const char *path, const char *prefix) {
    size_t length = strlen(prefix);
    return length > 0 && strncmp(path, prefix, length) == 0
           && (path[length] == '\0' || path[length] == '/');
}

int __real_faccessat(int directory, const char *path, int mode, int flags);
int __wrap_faccessat(int directory, const char *path, int mode, int flags) {
    if (fake_refused_access[0] != '\0' && strcmp(path, fake_refused_access) == 0) {
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

/* Whether realpath fails, as it does for a path that grew past PATH_MAX since it was examined. */
static bool fake_realpath_fails = false;

char *__real_realpath(const char *path, char *resolved);
char *__wrap_realpath(const char *path, char *resolved) {
    if (fake_realpath_fails) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return __real_realpath(path, resolved);
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
    fake_read_only_mount[0] = '\0';
    fake_noexec_mount[0] = '\0';
    fake_other_mount[0] = '\0';
    fake_statx_fails = false;
    fake_own_status = NULL;
    fake_unix_table = NULL;
    fake_euid_set = false;
    fake_realpath_fails = false;
    fake_file_count = 0;
    responses_sent = 0;
    memset(&last_response, 0, sizeof(last_response));
    every_response_continued = true;
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
    char anchor[PATH_MAX];
    char shown[PATH_MAX];
    check("an object resolves to itself",
          resolve_for_landlock("/proc/self/..", false, anchor, sizeof(anchor), shown, sizeof(shown))
              && strcmp(anchor, "/proc") == 0 && strcmp(shown, "/proc") == 0);
    check("a name to create resolves its parent and keeps the last name",
          resolve_for_landlock("/proc/../tmp/new", true, anchor, sizeof(anchor), shown,
                               sizeof(shown))
              && strcmp(anchor, "/tmp") == 0 && strcmp(shown, "/tmp/new") == 0);
    check("a name directly in the root has the root as its parent",
          resolve_for_landlock("/new", true, anchor, sizeof(anchor), shown, sizeof(shown))
              && strcmp(anchor, "/") == 0 && strcmp(shown, "/new") == 0);
    check("a missing object does not resolve",
          !resolve_for_landlock("/no/such/thing", false, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    check("a missing parent does not resolve",
          !resolve_for_landlock("/no/such/thing", true, anchor, sizeof(anchor), shown,
                                sizeof(shown)));
    check("a dot entry is no name to create",
          !resolve_for_landlock("/tmp/..", true, anchor, sizeof(anchor), shown, sizeof(shown)));
    check("nor is a single dot",
          !resolve_for_landlock("/tmp/.", true, anchor, sizeof(anchor), shown, sizeof(shown)));
    check("nor an empty last name",
          !resolve_for_landlock("/tmp/", true, anchor, sizeof(anchor), shown, sizeof(shown)));
    check("a relative name does not resolve",
          !resolve_for_landlock("tmp/x", true, anchor, sizeof(anchor), shown, sizeof(shown)));
    static char overlong[PATH_MAX + 8];
    memset(overlong, 'c', sizeof(overlong) - 1);
    overlong[0] = '/';
    overlong[sizeof(overlong) - 1] = '\0';
    check("a name longer than PATH_MAX does not resolve",
          !resolve_for_landlock(overlong, false, anchor, sizeof(anchor), shown, sizeof(shown)));
    char small[4];
    check("a resolved path that does not fit is refused",
          !resolve_for_landlock("/proc", false, small, sizeof(small), shown, sizeof(shown)));
    check("a parent that does not fit is refused",
          !resolve_for_landlock("/proc/new", true, small, sizeof(small), shown, sizeof(shown)));
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
    check("a create in a directory the mode refuses",
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
    fake_realpath_fails = true;
    check("a file whose path no longer resolves", silent(judged_open(secret, O_RDONLY)));
    fake_realpath_fails = false;
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
          last_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE && last_response.error == 0
              && last_response.val == 0 && last_response.id == FAKE_NOTIFICATION_ID);
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
              && last_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    check("every answer of the run was CONTINUE with error and value 0",
          responses_sent > 0 && every_response_continued);
}

static void test_arming_in_order(void) {
    printf("\nThe network enforcer arms the bind model, the filesystem enforcer after it\n");
    start_reporter();
    const char *network_enforcer[] = {"enforcer", "--no-filesystem", "--close-bind",
                                      "--bind-tcp", "8080", "--", "bash", NULL};
    const char *filesystem_enforcer[] = {"enforcer", "--rights=rx", in_tree("ro"), "--",
                                         "/bin/cat", NULL};
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
    const char *filesystem_enforcer[] = {"enforcer", "--rights=rx", in_tree("ro"), "--",
                                         "/bin/cat", NULL};
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
    const char *missing_rule[] = {"enforcer", "--rights=r", in_tree("ro/gone"), "--", "/bin/cat",
                                  NULL};
    check("rules that cannot be modelled turn reporting off",
          strstr(arm_with(missing_rule, ARMED_FILTERS), notice) != NULL);
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

int main(int argument_count, char *arguments[]) {
    if (argument_count == 3 && strcmp(arguments[1], "--quote") == 0) {
        static char out[REPORT_QUOTED_MAXIMUM];
        quote_like_bash(arguments[2], out, sizeof(out));
        fputs(out, stdout);
        return 0;
    }
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
    test_judging_unix_binds();
    test_judging_port_binds();
    test_arming_and_membership();
    test_arming_in_order();
    test_arming_refusals();
    test_reporter_handles();
    remove_tree();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
