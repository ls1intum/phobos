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
 * Called with --quote VALUE, the program prints VALUE quoted and nothing else, so the runner can
 * hold the quoting to bash's own over a corpus of names.
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../../core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.h"
#include "../../../core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.h"
#include "../../../core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.h"

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
    for (int index = 0; index < 150; index++) {
        snprintf(path, sizeof(path), "/denied/%d", index);
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
    for (size_t index = 0; index < REPORT_KEYS_MAXIMUM + 10; index++) {
        snprintf(path, sizeof(path), "/denied/%zu", index);
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
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
