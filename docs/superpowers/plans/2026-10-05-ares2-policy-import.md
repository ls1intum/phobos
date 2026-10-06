# Ares 2 Policy Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `phobos.sh --config` take an Ares 2 `security-policy.yaml` beside the existing `.cfg` files, translate every element of it that Phobos can enforce into the same specification a `.cfg` produces, and refuse, with file and line, every element whose translation would widen or narrow the sandbox without saying so.

**Architecture:** A strict YAML subset reader in bash turns the policy into flat, typed records with line numbers. An Ares importer checks those records against the Ares 2 schema (version 1), maps the file system, network and timeout domains onto the existing `.cfg` internals (so every translated value passes the same refusals a hand-written `.cfg` line passes), and reports the domains Phobos has no equivalent for. Everything that depends on a programming language comes from a **programming language configuration file**, one per value of Ares's `theFollowingProgrammingLanguageConfigurationIsUsed`, shipped as data beside the base policies: it names the base policies that configuration runs under and how each placeholder of that language is determined. The Phobos code itself knows no language. `phobos-policysystem.sh` picks the reader by file extension, selects the base policies the configuration names, and folds the result through the existing additive merge as an exercise configuration. No new language and no new package is added to the run-phase image; one new flag, `--project-root`, is added.

**Tech Stack:** bash (the policy system is bash today), GNU coreutils `realpath` (already required by `refuse_missing_realpath`), the existing `tests/harness.sh` suites, the protection matrix in the run-phase image.

**Spec:** this document. The design is embedded in Part A, because only this one file is committed for the planning pull request. The schema it rests on is Ares 2 at commit `18062fca42a5e337ec63b30655497c4071f765f8` (`ls1intum/Ares2`, 2026-10-05): `SecurityPolicy`, `SupervisedCode`, `ResourceAccesses`, the seven permission records, `PolicyValueValidator`, `SecurityPolicySchemaValidator`, `SecurityPolicyYAMLReader`, `YamlPlaceholderResolver`, and the instructor pages under `documentation/docs/instructor/policy-reference/`.

## Global Constraints

- Phobos stays additive: an imported policy is an exercise configuration and can only widen the base, never narrow it (AGENTS.md, "The sandbox is the product").
- Nothing in an Ares policy may be dropped without a refusal or a logged notice. A translation that would permit more than the policy states is refused with `PHB-EPOLICY` (exit 11), never approximated.
- Every refusal goes through `refuse_cfg`, so it reads `Policy invalid: <what>. Found in '<file>', line <n>. (PHB-EPOLICY)`.
- Every text file is LF; the reader refuses a carriage return, a byte order mark, a NUL byte and a tab, as `parse_cfg_policy` and `refuse_binary_cfg` do for a `.cfg`.
- One declaration per line in every language; every function in `core/*.sh` and `core/phobos-tools-*/*.sh` carries a comment saying what it does and what it assumes; no comments inside a function body.
- British English in prose, comments and messages; no em dashes.
- No bind, capability or allowed host is ever added to make a test pass.
- Acceptance and matrix suites run in an ordinary container: no `--privileged`, no `--cap-add`, no `--security-opt`.
- Branches use an allowed prefix (`feature/`); every pull request body follows `.github/PULL_REQUEST_TEMPLATE.md` and passes `PR_BODY="$(cat body.md)" java .github/scripts/CheckPullRequestTemplate.java`.
- The Ares 2 policy version accepted is exactly `1`; any other version is refused.
- **Phobos stays independent of any programming language.** No core script, helper or C source may name a language, a build tool, a JVM property or a language's directory layout. Everything language-specific lives in a programming language configuration file (A.4.2), selected by the value of `theFollowingProgrammingLanguageConfigurationIsUsed`, and in the base policies that file names. A reviewer rejects any change that puts a language into code.

---

# Part A: Design

## A.1 What is being imported

An Ares 2 policy is one YAML document. Its complete schema, read from the Ares 2 source at the pinned commit:

```yaml
thisPolicyFileCompliesToThePolicyVersion: 1          # int, required, exactly 1
regardingTheSupervisedCode:                          # mapping, required
  theFollowingProgrammingLanguageConfigurationIsUsed: JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ  # enum, required
  theSupervisedCodeUsesTheFollowingPackage: "org.example"  # string or null, optional
  theMainClassInsideThisPackageIs: "Main"            # string or null, optional
  theFollowingClassesAreTestClasses:                 # list of strings, required
    - "org.example.PenguinTest"
  theFollowingTestBehaviorIsConfigured: {}           # empty mapping, optional (no fields exist)
  theFollowingResourceAccessesArePermitted:          # mapping, required, all six lists required
    regardingFileSystemInteractions:                 # list of FilePermission
      - onThisPathAndAllPathsBelow: "allowed.txt"    # string, required
        readAllFiles: true                           # bool, required
        overwriteAllFiles: false                     # bool, required
        createAllFiles: false                        # bool, required
        executeAllFiles: false                       # bool, required
        deleteAllFiles: false                        # bool, required
    regardingNetworkConnections:                     # list of NetworkPermission
      - onTheHost: "www.example.com"                 # string, required
        onThePort: 80                                # int 0..65535, required, 0 means every port
        openConnections: true                        # bool, required
        sendData: true                               # bool, required
        receiveData: true                            # bool, required
    regardingCommandExecutions:                      # list of CommandPermission or bare strings
      - executeTheCommand: "ls"
        withTheseArguments: ["-l"]
    regardingThreadCreations:                        # list of ThreadPermission
      - createTheFollowingNumberOfThreads: 10
        ofThisClass: "org.example.Worker"
    regardingPackageImports:                         # list of PackagePermission
      - importTheFollowingPackage: "java.util"
    regardingTimeouts:                               # list of ResourceLimitsPermission
      - timeout: 120000                              # long, milliseconds, 1..Long.MAX_VALUE
```

What Ares itself enforces about the file: unknown keys are refused at every level, duplicate keys are refused (`STRICT_DUPLICATE_DETECTION`), exactly one document is allowed, required keys must be present and not null, booleans must be booleans (`yes`, `no`, `on`, `off` are read as strings, so they fail the boolean check), integers must be integral, and four placeholders are expanded in every string after parsing: `${PROJECT_ROOT}`, `${java.home}`, `${user.home}`, `${java.io.tmpdir}`; any other `${...}` in a path is refused.

The eight values of `theFollowingProgrammingLanguageConfigurationIsUsed` are the full cross product `JAVA_USING_{MAVEN,GRADLE}_{ARCHUNIT,WALA}_AND_{ASPECTJ,INSTRUMENTATION}`. Every value is Java. There is no Ares 2 configuration for Python or any other language, so "every kind of programming language configuration" means these eight.

Ares 2 already contains a Phobos writer, `JavaPhobosTestCase.writePhobosSecurityTestCaseFile`, which emits `[readonly]`, `[write]`, `[network]` with `deny *`, and `[limits]`. Phobos refuses all four of those today (`[readonly]`, `[network]` and the `deny` line are unknown), and Ares never dispatches the result. This plan does not depend on that writer. Decision (Q1): Phobos translates the Ares file itself; the writer in Ares is outside this repository and not touched by this plan.

## A.2 What Phobos is, and why an import can only add

Phobos confines the whole process tree a grading command starts: Gradle or Maven, the JVM, the JDK, the test framework, the test classes and the student code alike. Ares confines the student package inside the JVM and exempts the test classes and its own infrastructure. An Ares policy that grants "read `allowed.txt`" means "the student code may read that one file and nothing else", but a Gradle build cannot run at all with that alone, which is why the shipped `BaseLanguage-java.cfg` grants the whole project tree, the JDK and `/root/.gradle`.

So an imported policy is folded on top of the base, as every `--config` file is. It adds what it grants beyond the base, and it cannot express "nothing else": a narrowness that lies inside the base stays Ares's job in the JVM. This is the existing, deliberate model (AGENTS.md: "Do not 'fix' the union back to a narrow-only exercise merge"), and the import makes it loud rather than hiding it: see A.6, the covered-entry skip, and the summary line in A.7.

## A.3 Approaches considered

1. **A strict YAML subset reader in bash inside the policy system (chosen).** No new runtime dependency in the run-phase image, whose `/usr` the base grants `rx` to the submission, so every interpreter added there is one the student code can run too. The reader knows the line of every value, so `refuse_cfg` messages carry file and line naturally. It refuses every YAML feature outside the subset, so it can be wrong only by refusing, never by reading a value differently from Ares. Cost: a few hundred lines of bash and a careful test suite.
2. **A Python helper with PyYAML in the run-phase image.** Full YAML, less code. Rejected for v1: it adds Python and a third-party package to the image the submission runs in, PyYAML's YAML 1.1 resolution differs from Jackson's in places (`yes`, sexagesimals), so it would still need the same type rules, and line numbers need the lower-level event API.
3. **Ares emits the current `.cfg` format and Phobos keeps reading only `.cfg`.** The schema then lives in exactly one place, Ares's Jackson validator, and Phobos gains nothing to maintain. Rejected by decision Q1: Phobos translates the file itself.

A fourth shape, an offline converter that writes a reviewable `.cfg`, is not needed: `phobos-policysystem.sh --debug` already prints the effective specification, which is what such a converter would show.

## A.4 Where the parsing lives

| Concern | Decision |
| --- | --- |
| Format detection | By file extension inside `fold_cfg_into` in `core/phobos-policysystem.sh`: a `--config` file whose name ends in `.yaml` or `.yml` is read by the Ares importer, every other name by `parse_cfg_policy` exactly as today. Both readers fail closed on the other format (a YAML file has content before any `[section]`; a `.cfg` has no YAML root keys), so a misnamed file is refused, never misread. Detection needs no flag, so `phobos.sh` and the standalone `--config` of every layer script work unchanged, because each already hands its `--config` files to `phobos-policysystem.sh` (only `--project-root`, A.5.2 step 6, is new, and only on `phobos.sh` and `phobos-policysystem.sh`). A base is always a `.cfg`, chosen as A.6 describes; an Ares policy is always an exercise configuration. Decision Q14. |
| YAML reader | New file `core/phobos-tools-policysystem/phobos-policy-yaml.sh`, function `read_yaml_subset`, sourced by `phobos-common.sh` after `phobos-policy-parse.sh`. |
| Ares schema and mapping | New file `core/phobos-tools-policysystem/phobos-policy-ares.sh`, function `parse_ares_policy`, sourced after the YAML reader. It writes the same outputs `parse_cfg_policy` writes (`PARSED_FS_DIR`, `PARSED_NET_FILE`, `PARSED_BIND_FILE`, `PARSED_ACCEPT_FILE`, the `PARSED_*` limits) plus `PARSED_ARES_CONFIGURATION` (the configuration name, as written) and `PARSED_ARES_SKIPPED`, the number of rows the covered-entry skip left out. It contains no language name. |
| Programming language configurations | New data folder `core/config/language-configurations/`, one file per configuration name (A.4.2), read by a new language-independent loader `core/phobos-tools-policysystem/phobos-language-configuration.sh`. |
| Image | The run-phase Dockerfile copies `config/language-configurations/` beside the base policies, and ships every base a shipped configuration names. No package is added. |
| Flag | `--project-root <dir>` on `phobos.sh` and `phobos-policysystem.sh` (A.5.2 step 6). |
| Shell | bash, as every file in `core/phobos-tools-policysystem/` is, and as `refuse_cfg` (which relies on `${var@Q}` and on ending the run) requires. |

### A.4.1 The YAML subset

The reader accepts exactly this, and refuses everything else with a message that names the construct and the line:

- One document. An optional `---` on the first significant line; a second `---` or any `...` is refused.
- Text with LF endings. A carriage return, a byte order mark, a NUL byte or a tab character anywhere is refused (tabs are not valid YAML indentation, and refusing them everywhere keeps the record format, which is tab-separated, unambiguous).
- The whole file must be valid UTF-8 (decision Q15). The reader checks every line before it reads any as YAML, against the well-formed byte sequences of RFC 3629 matched in the C locale, and refuses the file, naming the first line that fails, when it holds an invalid or overlong sequence, an encoded surrogate, or a code point above U+10FFFF. `iconv -f UTF-8 -t UTF-8` is not enough for this: measured in the test image, glibc's decoder accepts U+110000 (`f4 90 80 80`) and the old five-byte forms. Inside values and keys, control characters are refused: C0 (U+0000 to U+001F), DEL (U+007F) and C1 (U+0080 to U+009F), and the bidirectional formatting characters U+202A to U+202E and U+2066 to U+2069, which make a path read differently on a terminal from what it is. Every other code point is allowed, so a path with a non-ASCII name works; keys stay ASCII, since every key of the schema is. A comment may hold any valid UTF-8 except NUL, CR, tab and a byte order mark, which is refused anywhere in the file, not only at its start. Boolean-like words are lower-cased in the C locale, so that a Turkish locale's dotless i cannot turn `.INF` into a word the check misses. Messages quote such a value with `${value@Q}`, which shows it as it is in a UTF-8 locale and escapes it in the C locale.
- Comments: a `#` at the start of a line after spaces, or a `#` preceded by a space outside quotes.
- Block mappings, `key: value` or `key:` followed by a more indented block. A key is `[A-Za-z][A-Za-z0-9]*`; every key in the Ares schema has that shape, so a quoted key or any other key is refused as unknown.
- Block sequences, `- value` and `- key: value` (a mapping item whose further keys are indented to the column after `- `), indented under their key or at the key's own column (both are valid YAML and both appear in practice).
- The empty flow collections `[]`, `[ ]`, `{}` and `{ }` as a whole value. A non-empty flow collection (`["-l"]`) is refused with a hint to use block style.
- Scalars:
  - double-quoted, with the escapes `\\` and `\"` only (any other escape is refused, because a path with `\n` in it would be read differently by different YAML readers' users);
  - single-quoted, with `''` for a quote;
  - plain, on one line. A plain scalar that begins with one of `- ? : , [ ] { } # & * ! | > ' " % @` or a backtick is refused, which covers anchors, aliases, tags, block scalars and directives.
- Typing of a plain scalar follows the resolution Jackson's YAML reader applies with `PARSE_BOOLEAN_LIKE_WORDS_AS_STRINGS`, narrowed so that every value either reader might type differently is refused rather than guessed:
  - `true` and `false` are `bool`; `True`, `TRUE`, `False`, `FALSE`, `yes`, `no`, `on`, `off`, `y`, `n` in any case are refused as ambiguous;
  - `null`, `Null`, `NULL`, `~` and an empty value are `null`;
  - `0` and `[1-9][0-9]*` are `int`; any other spelling that a YAML 1.1 reader could read as a number (a sign, a leading zero, `0x`, `0o`, `0b`, an underscore, a dot, an exponent, a colon between digits, `.inf`, `.nan`) is refused as ambiguous;
  - everything else is `str`.
- A quoted scalar is always `str`.
- Duplicate keys in one mapping are refused, naming both lines.
- A line indented deeper than its context allows, a continuation line, and a `-` alone on a line are refused.

The contract against Ares's reader, case by case. Ares reads with Jackson's YAML factory (SnakeYAML, YAML 1.1 resolution) and `FAIL_ON_UNKNOWN_PROPERTIES`, `FAIL_ON_NULL_FOR_PRIMITIVES`, `STRICT_DUPLICATE_DETECTION` and `PARSE_BOOLEAN_LIKE_WORDS_AS_STRINGS`, then expands placeholders in string scalars only, then validates. "Same" means Phobos reads the identical typed value; every other row is a refusal, so Phobos is never laxer than Ares. Each row is one case of `yaml_subset.sh`:

| Input value | Ares reads | Phobos |
| --- | --- | --- |
| `true`, `false` | boolean | same |
| `True`, `TRUE`, `False` | boolean | refused (ambiguous spelling) |
| `yes`, `no`, `on`, `off`, `y`, `n` | string, so a boolean field fails validation | refused |
| `80`, `0` | integer | same |
| `080`, `0x50`, `0o120`, `+80`, `8_0`, `1:20`, `80.0`, `8e1` | integer or float under YAML 1.1 | refused |
| `"80"`, `'80'` | string, so an integer field fails validation | `str`, so the schema check refuses it |
| `null`, `~`, empty | null | same |
| `"a\nb"` (escape other than `\\`, `\"`) | string with a control character | refused |
| `&a x`, `*a`, `!!str x`, `\|`, `>` | anchor, alias, tag, block scalar | refused |
| `["-l"]` | sequence with one item | refused, block style required |
| `[]`, `{}` | empty sequence, empty mapping | same |
| a key twice in one mapping | refused | refused |
| a second document | refused | refused |
| a tab, a carriage return, a byte order mark, a NUL | accepted in some positions | refused everywhere |
| `"/srv/übung"` (valid UTF-8) | string | same |
| an invalid UTF-8 byte sequence | refused by the decoder | refused, naming the line |
| a C1 control or a bidirectional override in a value | string | refused |
| `-l` as a plain item | string | refused (plain scalar starting with an indicator); write `"-l"` |
| `::1` plain | string under SnakeYAML | refused (starts with an indicator); write `"::1"` |

The output is a records file, one line per node:

```
<line>\t<path>\t<type>\t<value>
```

where `<path>` is `.` for the root and `.key`, `[index]` steps below it (for example `.regardingTheSupervisedCode.theFollowingResourceAccessesArePermitted.regardingNetworkConnections[2].onThePort`), `<type>` is one of `map`, `seq`, `str`, `int`, `bool`, `null`, and `<value>` is empty for `map`, `seq` and `null`. Containers are recorded too, so an empty list is visible as a `seq` with no children.

### A.4.2 Programming language configuration files

Phobos must not know any programming language (Global Constraints). Ares names the language in `theFollowingProgrammingLanguageConfigurationIsUsed`; everything that depends on it is data in one file per configuration name, `core/config/language-configurations/<NAME>.cfg`, shipped beside the base policies (`${PHOBOS_HOME}/language-configurations/<NAME>.cfg` in the image). The loader `phobos-language-configuration.sh` is language-independent: it reads the file with the same discipline as a `.cfg` (LF only, no BOM, no NUL, `refuse_cfg` with file and line, unknown sections and keys refused) and knows only generic primitives.

```ini title="core/config/language-configurations/JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ.cfg"
[base]
BaseLanguage-java.cfg

[placeholders]
java.home      = command-ancestor java 2
user.home      = password-database home
java.io.tmpdir = fixed /tmp

[connect]
allow localhost udp
```

- **`[base]`** names one or more base policy files, each of which must exist. One resolution rule, used everywhere in this plan: a bare file name (no slash) is resolved beside `phobos-policysystem.sh`, where today's `Base*.cfg` live; a name with a slash is resolved under `language-configurations/`, and `..`, an absolute path and a symbolic link leading out of either folder are refused. A run that imports an Ares policy folds exactly these bases and no other `Base*.cfg` (A.6), so a Java configuration runs under the Java base only (decision Q8) and a Maven configuration under the Maven base (decision Q7).
- **`[placeholders]`** names each placeholder this configuration supports and how Phobos determines its value itself (decision Q3), with four generic primitives and nothing else:
  - `environment <VARIABLE> [<fallback>]`: the variable's value in the environment `phobos.sh` was started in, or the fallback when it is unset or empty;
  - `command-ancestor <command> <levels>`: the command looked up on the `PATH` of that environment, resolved through every symbolic link with `realpath -e`, then that many directory levels up (`java` at `/opt/java/openjdk/bin/java` with 2 gives `/opt/java/openjdk`);
  - `fixed <absolute path>`: a constant;
  - `password-database home`: the home field (the sixth) of the password database entry of the real uid of the process that runs `phobos.sh`, as `getent passwd "$UID"` prints it. It is refused, with `PHB-EPOLICY`, the configuration file and the line, when the database holds no entry for the uid, when the entry is not seven colon-separated fields, when the home field is shorter than two characters (empty or `/`), relative or not an existing directory, or when the entry holds a control character or a newline; a refusal names the uid, never the whole entry, which may hold a password field and a real name; `getent` failing in any other way, missing among them, ends the run with `PHB-ERUNTIME`. `home` is the only field it takes. Decision R5.
  A placeholder is determined only when it is used (decision R6): loading a configuration checks every `[placeholders]` line (a known primitive, its arguments, a placeholder named once) but determines nothing, and the first use of a placeholder determines its value and keeps it, so a placeholder used twice asks its source once and one that is never used never asks it. Every determined value must be an absolute path to a directory that exists, or the placeholder is refused when it is used, naming the configuration file and the placeholder's line; a placeholder the configuration does not name is refused where it is used. `environment` reads the process environment through `printenv`, never a shell variable of the script, and `command-ancestor` searches the absolute entries of the `PATH` alone, never the current directory.

  Measured in the current run-phase image (JDK 17.0.16), which is why the Java values are what they are: the JVM takes `java.io.tmpdir` to be `/tmp` on Linux whatever `TMPDIR` says (`TMPDIR=/var/tmp java -XshowSettings:properties` prints `java.io.tmpdir = /tmp`), so it is `fixed /tmp`; reading `TMPDIR` would expand `${java.io.tmpdir}` to a directory Ares does not mean. The JVM takes `user.home` from the password database, not from `HOME` (`HOME=/var/tmp` still prints `user.home = /root`, and a user with no password entry gets `?`), so it is `password-database home` (decision R5). From JDK 19 the JVM falls back to `HOME` when there is no entry or the home is shorter than two characters (JDK-8280357; measured by the review on 25.0.4: a home of `/` gives `user.home` = `$HOME`), which is why exactly those cases are refused. `environment HOME` would agree with Ares only while `HOME` is left as the image sets it. As uid 65534, whose entry names `/nonexistent`, the JVM prints `user.home = /nonexistent` and the primitive determines the same value, which is refused because it is not an existing directory. Since a placeholder is determined only when it is used (decision R6), a run as such a user under a Java configuration starts when its policy never writes `${user.home}` and is refused, as before, when it does; measured in the run-phase image as uid 65534 with `HOME=/var/tmp`. `command-ancestor java 2` gives `/opt/java/openjdk`, which is the JVM's `java.home`. The trust invariant, stated once and pinned by a test: a placeholder value is determined only from the environment and the `PATH` of the process that runs `phobos.sh`, from the image, and from the configuration file, all of which the grader sets before the command is started and none of which the submission can reach, since the specification is built before the command exists. Phobos never reads the command's environment, its current directory, or any file of the assignment tree to determine a value. A grading setup that hands `phobos.sh` an environment the submission influenced breaks this invariant; SECURITY.md states it as an integration requirement beside the existing one for the exercise configuration. The value is written to the debug log.
- **`[connect]`** (from pull request 4, decision R1) holds ordinary `[connect]` lines, each read by the same `append_connect_rule` as a `.cfg` line and refused with the same messages, file and line. Its rows are written into the base's `net.rules` when base selection (A.6) picks this configuration, so they are folded before any exercise configuration, exactly as the `[connect]` rows of a base named in `[base]` would be. Only a run that imports an Ares policy naming this configuration loads the file at all, so a `.cfg`-only run never gets these rows. Every shipped configuration file, the four `GRADLE` ones and later the four `MAVEN` ones, carries exactly one row, `allow localhost udp`: a `udp` loopback rule with no port, which A.5.3 explains. The rule lives here and nowhere in Phobos core: no script, helper or C source adds it, and it is not written into `BaseLanguage-java.cfg`, which every `.cfg`-only Java run folds and which would then permit it to every such run. The section accepts only a loopback rule that names no port, `allow <host> [udp|tcp]` with a host `is_loopback_host` accepts (`localhost`, `::1`, `127.*`), and refuses every other line, a port or a non-loopback host included, with file and line. A programming language configuration exists to say which base a run uses; it must not become a second, less visible place for egress rules. A rule that reaches beyond loopback belongs in a base, whose pull request states it.
- `${PROJECT_ROOT}` is not a language matter and is not configured here (A.5.2 step 6).
- A configuration name with no file is refused: "the programming language configuration 'X' has no file 'language-configurations/X.cfg' beside phobos-policysystem.sh, so Phobos does not know which base policy it runs under". A future Ares configuration for another language therefore needs a data file and a base policy, never a code change.
- The eight Java files differ only in `[base]`; `[placeholders]` and `[connect]` are the same in all eight. The four `GRADLE` ones name today's `BaseLanguage-java.cfg`, which was pruned on a Gradle exercise; it keeps its name, so the matrix, the acceptance suites, the documentation and every operator's run are untouched. The four `MAVEN` ones need a base pruned on the Maven reference exercise of A.4.3 (A.11, pull request 7). Until that base exists, the four `MAVEN` configuration files are not shipped, so a Maven policy is refused with the missing-configuration message instead of failing late with `EACCES` on `~/.m2` (decision Q7).
- Where the Maven base lives is fixed now, and it is shipped in pull request 7: a run without an Ares policy folds every `Base*.cfg` beside `phobos-policysystem.sh`, as today, so a second Java base must not sit there, or every `.cfg`-only run in the image would gain the Maven grants without a word. The Maven base therefore lives in `language-configurations/bases/`, which the `Base*.cfg` glob does not reach, and a `[base]` entry may name a file there (`bases/BaseLanguage-java-maven.cfg`). A `[base]` entry is resolved against the folder of `phobos-policysystem.sh` for a bare name and against `language-configurations/` for a name with a slash, and nothing else.

### A.4.3 The Maven reference exercise (decisions R2 and R3)

This section is the one definition of the exercise. The prune plan of pull request 162 (`docs/superpowers/plans/2026-10-05-prune-on-the-layers.md`) states the input contract every prune exercise meets (its A.6.8) and consumes this exercise in its Task 14.1; it refers here rather than repeating it.

- **Who builds it, and where.** It is built in this repository, by us, in pull request 6 of A.11, and taken from no Artemis instance or other repository. It lives at `var/tmp/testing-dir/java-maven/maven-reference/`, where the prune container finds its inputs (`var/tmp/testing-dir/<key>/<exercise>/`). `java-maven` is a key of its own because the prune orchestrator unions every exercise of one key into one base: under `java`, the Maven grants would be merged into the Gradle base, against decision Q7. The key yields `BaseLanguage-java-maven.cfg`, the name the `MAVEN` configurations' `[base]` uses.
- **It runs Ares 2 the way an Artemis Maven exercise does (decision R3).** Its shape is taken from Artemis's Java Maven test template, `src/main/resources/templates/java/test/maven/projectTemplate/` (`pom.xml` and `SecurityPolicy.yaml`, branch `develop` at `a5bb83b`, 2026-10-04), and from Artemis's local CI script `templates/localci/java/build_and_run_tests.sh`, which copies the student repository into `assignment/` beneath the test repository and runs `mvn clean test` there. The template, read rather than guessed, brings: Ares 2 (`de.tum.cit.ase:ares` 2.1.5, scope `provided`, which brings JUnit, AssertJ, ArchUnit, WALA, AspectJ, Byte Buddy, JavaParser and the rest of its own dependencies); `org.aspectj:aspectjrt` 1.9.25.1; AspectJ weaving of the student classes with `dev.aspectj:aspectj-maven-plugin` 1.14.1 and `aspectjtools` 1.9.25.1; the Ares agent (`ares` 2.1.5, classifier `agent`) and `aspectjrt` copied by `maven-dependency-plugin` 3.11.0 to `target/ares/` and put on Surefire's `argLine` as `-javaagent` and `-Xbootclasspath/a`; Ares's reserved-package check through `maven-antrun-plugin` 3.2.0; `maven-compiler-plugin` 3.16.0 and AspectJ compliance both at release 25; `maven-resources-plugin` 3.5.0; `maven-surefire-plugin` 3.6.0. The build therefore always weaves the aspects and always loads the agent; which analysis (ArchUnit or WALA) and which enforcement (AspectJ or instrumentation) Ares uses at run time is chosen by the policy file's configuration name.
- **What it contains**, and nothing more:

  ```
  var/tmp/testing-dir/java-maven/maven-reference/
    build_script.sh       executable bash: exec mvn --offline --batch-mode -DfailIfNoTests=true clean test
    prune.json            {"report_globs": ["target/surefire-reports/TEST-*.xml"], "declared_hosts": []}
    pom.xml               the template's pom.xml, placeholders filled, three blocks removed (below), maven-clean-plugin 3.2.0 pinned
    SecurityPolicy.yaml   the template's policy shape: JAVA_USING_MAVEN_ARCHUNIT_AND_ASPECTJ, package de.phobos.reference,
                          test class de.phobos.reference.AdderTest, every resource list empty
    assignment/src/de/phobos/reference/Adder.java     one class, one static method
    test/de/phobos/reference/AdderTest.java           @Public, @Policy("SecurityPolicy.yaml"), two passing tests with @StrictTimeout
  ```

  Filled placeholders: `${packageName}` is `de.phobos.reference`, `${studentWorkingDirectory}` is `/assignment/src` (Artemis's `STUDENT_WORKING_DIRECTORY`), `${packaging}` is `jar`. Removed: the static code analysis plugins (Artemis runs them only when an exercise enables them, and not as part of `mvn clean test`), and the Maven Central mirror repositories (the build is offline). Added: `maven-clean-plugin` 3.2.0, which the template leaves to Maven's default, so that no default chooses a version. The build script adds `--offline`, `--batch-mode` and `-DfailIfNoTests=true` to Artemis's `mvn clean test`, nothing else.
- **Every artefact pinned, and pre-loaded.** The direct versions are fixed in `pom.xml`, and the transitive ones by the published POMs, which use no version ranges. The bytes are fixed by a committed manifest, `docker/run_phase/java/maven-repository.sha256`, holding the SHA-256 of every file the build needs that the base image does not already hold. Measured on 2026-10-05 in `ls1tum/artemis-maven-template:java25-1` (the local pull resolved to `sha256:b8393cc0fd72...`, created 2026-10-02; Java 25.0.4.1, Maven 3.9.16, Ubuntu 24.04.5, JDK at `/opt/java/openjdk`), in an ordinary container with `--network none`: its seeded `/root/.m2/repository` already holds Ares 2.1.5 and its agent jar, `aspectjrt` and `aspectjtools` 1.9.25.1, `aspectj-maven-plugin` 1.14.1, the compiler, resources, Surefire, antrun, dependency and clean plugins at the template's versions, and WALA core 1.8.0; but the offline build of this exact shape fails because ten jars of the closure are absent although their POMs are present: `archunit` 1.5.0, `mockito-core` 5.23.0, `objenesis` 3.3, `byte-buddy` and `byte-buddy-agent` 1.18.13, `guava` 33.6.0-jre, `jackson-core` and `jackson-databind` 2.22.2, `json` 20260522, `snakeyaml` 2.5. Pre-loading is therefore a real step, and it happens in the run-phase image (next item), not in the prune image alone.
- **The run-phase image carries the same artefacts as the prune image, by construction.** The base pruned from this exercise names files under `/root/.m2/repository` by path. If the grading image held other versions, a graded Ares build would read jars the base does not name and be refused with `EACCES`; if it lacked them, the base would name paths that do not exist, which the filesystem layer drops, and the build would stop at Maven's offline line. So the pre-loading lives in `docker/run_phase/java/Dockerfile`, and the prune image, which is built `FROM` the run-phase image and adds nothing under `/root/.m2` (prune plan A.6.8), inherits exactly those bytes. Two changes, in two pull requests:
  1. Pull request 5 moves both stages of the run-phase Dockerfile from `ls1tum/artemis-maven-template:java17-25` to `ls1tum/artemis-maven-template:java25-1`, pinned by its multi-architecture index digest (looked up with `docker buildx imagetools inspect`, never a single-platform digest). That is the image Artemis builds Java exercises in by default (`application.yml`, `java: default`), and the only one in which the template's `release 25` compiles; Ares 2.1.5 itself is Java 17 bytecode (class file major version 61), but the template compiles the student and test code for release 25. Every run, Gradle runs included, then runs on JDK 25 and Maven 3.9.16 (decision R4). What that means for the Java base and for Gradle is A.4.4.
  2. Pull request 6 adds a stage `maven-repository` that copies this exercise into the build, records the path and SHA-256 of every file under `/root/.m2/repository` before and after running the exercise's own `mvn --batch-mode --strict-checksums clean test` once, with the network the image build has anyway (as `apt-get` does), and refuses the image unless two checks pass: the sorted list of paths that are new or changed after the run equals the sorted list of paths in `maven-repository.sha256` exactly (`diff`, so an added file the manifest does not list fails as well as a listed file that was not produced), and `sha256sum --strict -c maven-repository.sha256` reports every line `OK`. The final stage copies that repository over the base image's. The exercise's sources stay in the discarded stage; only the repository enters the grading image. `.github/scripts/assemble-run-phase-context.sh` adds the exercise and the manifest to the build context.
  The added jars are reachable only where a policy grants `/root/.m2`; no shipped `Base*.cfg` does, so a `.cfg`-only run gains nothing from them.
- **Offline, every run.** `--offline` keeps Maven from contacting a remote repository even where a network exists, and the prune container runs with `--network none` as well (AGENTS.md: a prune run must not reach the network for anything it did not intend to). An artefact missing from the image's repository ends the build at once with status 1 and `Cannot access central (https://repo.maven.apache.org/maven2) in offline mode and the artifact ... has not been downloaded from it before`; the pruner reads that, in its unsandboxed baseline, as an infrastructure failure and aborts, never as a grant (prune plan A.8).
- **No false success.** Surefire reports a project without tests as `[INFO] No tests to run.` and status 0, and `-DskipTests` as `[INFO] Tests are skipped.` and status 0, Maven's counterparts of Gradle's `NO-SOURCE`; `-DfailIfNoTests=true` turns the first into status 1 (`No tests to run!`). Measured on 2026-10-05 with Maven 3.9.11 and Surefire 3.5.3 on Java 17 and again with Maven 3.9.16, Surefire 3.6.0 and JUnit 6.1.3 on Java 25 (`java25-1`), with the same lines. The pruner never trusts the status anyway: its verdict reads the Surefire XML reports and recognises both lines (prune plan A.8 and Task 4.1). It also refuses an exercise whose committed copy already matches one of its report globs, so a stale report cannot stand in for a run.
- **Not yet measured**, because the repository is incomplete until pull request 6: the whole Ares-supervised build offline, its run under `phobos.sh` with a permissive exercise configuration and every layer on, and whether an offline Ares build writes anything under `/root/.m2` (checked by comparing paths and SHA-256 of the whole repository before and after the run). Pull request 6 measures all three before it is opened (Task 6b). Measured earlier for a JUnit-only shape on Java 17, and still true as far as it goes: Maven passes under every layer with a permissive configuration (it starts no daemon, so the group lock's `setsid` refusal does not arise), and an offline run writes nothing under `/root/.m2`.
- **Its base is produced by the prune plan's pruner, and nothing else.** The base is not written by hand and not produced by the Bubblewrap pruner: the layer pruner of pull request 162 prunes this exercise (its Task 14.1), its orchestrator writes `BaseLanguage-java-maven.cfg`, and pull request 7 of A.11 adopts that file as `core/config/language-configurations/bases/BaseLanguage-java-maven.cfg`, with the pruner's record (`java-maven_maven-reference.json`) attached and every grant stated as "this now permits X, which it did not permit before" for a run under a `MAVEN` configuration.
- **The four `MAVEN` configurations.** The exercise runs the template's configuration, `JAVA_USING_MAVEN_ARCHUNIT_AND_ASPECTJ`. The other three load the same jars and the same agent but analyse with WALA or enforce through instrumentation, and may read files the first does not. Pull request 7 therefore runs the exercise under `phobos.sh` with the pruned base once per configuration name, with only the name in `SecurityPolicy.yaml` changed on a throwaway copy, and ships a `MAVEN` configuration file only for a name whose run passes. A name that fails is pruned as one more exercise under the same key, which the orchestrator unions into the same base, before its file is shipped; until then it stays refused for want of its file, which fails closed.
- **What it changes in the repository.** It is the first Java beyond the two template checkers under `.github/scripts/`: pull request 6 corrects the sentence in CLAUDE.md that names Java for exactly one file and the one in AGENTS.md that calls the checker the only Java here (both already miss `CheckReleaseTemplate.java`). CodeQL's `java-kotlin` job compiles only the pull request template checker (`build-mode: manual`), so the exercise is not analysed and needs no CodeQL change. `ec` covers its files: LF, final newline, no tabs.

### A.4.4 The run-phase image on JDK 25, the Gradle reference exercise and the Java base (decision R4)

Every graded run moves to JDK 25 with the image (pull request 5). Measured on 2026-10-05 in an ordinary container with `--network none`, comparing `phobos-run-phase:ci` (the current image, JDK 17.0.16) with `ls1tum/artemis-maven-template:java25-1` (JDK 25.0.4.1), and running the shipped Phobos lifted out of the current image inside the second:

- **No base path names a JDK 17 location.** Every one of the 24 paths `BaseLanguage-java.cfg` names that exists in the JDK 17 image exists in the JDK 25 image too. The JDK lives at `/opt/java/openjdk` in both, and the base names its directories (`bin`, `conf`, `conf/security`, `lib`, `lib/server`), not files of one release. The paths missing in both are the same: the exercise's own (`/var/tmp/testing-dir/...`) and the x86-only `/lib/x86_64-linux-gnu` and `/lib64` on an arm64 host. So no path has to follow the JDK.
- **The shipped base still does not carry a JDK 25 Gradle build.** Gradle 9.0.0, which the JDK 17 image seeds, cannot run on Java 25 at all: Gradle's compatibility matrix lists 9.1.0 as the first release that runs on Java 25. The JDK 25 image seeds Gradle 9.8.0, which is exactly what Artemis's Gradle template pins (`gradle-wrapper.properties`, `develop` at `a5bb83b`). A Gradle 9.8.0 build with the shipped base under `phobos.sh`, every layer on, failed in three successive places, each attributable: (1) even with `--no-daemon`, Gradle forked a single-use daemon ("To honour the JVM settings for this build a single-use Daemon process will be forked"), whose `setsid` the timeout's group lock refused (`could not setsid() (errno 13)`); (2) once the build ran in the launching JVM, it could not create its project cache `/var/tmp/testing-dir/.gradle`, which the base grants only `rx`; (3) `clean` could not delete `/var/tmp/testing-dir/build`, which the filesystem layer had materialised as an empty file because the base names it as a missing write path, and whose removal needs a right on `/var/tmp/testing-dir` the base does not grant. The base was pruned on JDK 17 with another Gradle. It is therefore re-pruned on JDK 25, in pull request 5, as part of the same change as the image; an image switch without it would break every Gradle grading run.
- **The fork is avoided inside the exercise, not in Phobos.** Gradle forks whenever an immutable JVM argument of the launching JVM differs from what the build requests, or the instrumentation agent's status differs. Measured: `org.gradle.daemon=false`, `org.gradle.jvmargs=-Xms64m -Xmx512m -Dfile.encoding=UTF-8` and `org.gradle.internal.instrumentation.agent=false` in the test repository's `gradle.properties`, together with `DEFAULT_JVM_OPTS='"-Xmx512m" "-Xms64m"'` in its `gradlew` (the wrapper's own `-Xmx64m` is below what Gradle accepts in process, "The maximum heap size is insufficient"), make Artemis's unchanged `./gradlew clean test` run in the launching JVM: no "single-use" line and no `setsid`, directly and under `phobos.sh`. All four live in the test repository, which grading uses as it is, so grading needs no flag and no environment variable, and no line of Phobos core changes; the group lock stays as it is (prune plan decision 8). `org.gradle.internal.instrumentation.agent` is an internal Gradle property, which a later Gradle may rename: a Gradle bump is therefore re-measured in the pull request that makes it, and a returning fork shows up as a fixed-rule refusal of `setsid` in the prune (prune plan A.6.4, B2) before any grant, never as a silent failure. The same settings also pin the heap of the JVM that runs Gradle, which the prune plan's decision 4 needs for `mem_mb`.
- **The Gradle reference exercise, defined here once,** beside the Maven one of A.4.3 and in the same shape. It lives at `var/tmp/testing-dir/java/gradle-reference/`, under the key `java` that yields `BaseLanguage-java.cfg`. It is Artemis's Gradle test template (`build.gradle`, `settings.gradle`, `gradle/AresReservedPackages.gradle`, the wrapper, `SecurityPolicy.yaml` with `JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ`) with the static code analysis, mirror and sequential blocks removed and `${studentWorkingDirectoryNoSlash}` filled with `assignment/src`; the same `Adder` class and the same two Ares-annotated tests as the Maven exercise; the four settings above; `gradle-wrapper.properties` pinning Gradle 9.8.0 with its `distributionSha256Sum`; `build_script.sh` running `exec ./gradlew --offline clean test`; and `prune.json` with `"report_globs": ["build/test-results/test/*.xml"]`, `"declared_hosts": []` and `"heap_pinned": true`. The template's plugins (`io.freefair.aspectj.post-compile-weaving` 9.8.0, `com.teamscale` 39.0.0) resolve from the image's Gradle cache offline. Ares 2's closure does not: an offline build in `java25-1` fails for `byte-buddy` and `byte-buddy-agent` 1.18.13, `jackson-databind` 2.22.2 and more, the Gradle side of the gap A.4.3 measured for Maven.
- **Pre-loaded like Maven.** A stage `gradle-repository` in the run-phase Dockerfile runs this exercise's own `./gradlew clean test` once online and refuses the image unless the set of files it added or changed under `/root/.gradle/caches/modules-2/files-2.1` equals the paths of a committed manifest, `docker/run_phase/java/gradle-repository.sha256`, and `sha256sum --strict -c` passes, exactly as the Maven stage does with its own manifest (A.4.3). The final stage copies that cache; the prune image inherits it.
- **The re-pruned base.** Pull request 5 runs the prune plan's pruner (merged with that plan's pull request 8) on this exercise, under the key `java`, against the run-phase image built from pull request 5's own branch, and replaces `core/config/BaseLanguage-java.cfg` with the orchestrator's `BaseLanguage-java.cfg`. Its body lists every row the new base adds or widens as "this now permits X, which it did not permit before", and every row it drops or narrows. One kind of row is never dropped by the prune: a base entry an ancestor already covers, such as `/usr/bin` with `rx` beneath `/usr` with `rx` (AGENTS.md, "A base entry an ancestor already covers is not dead code"), which decides whether an exercise configuration naming exactly that path is accepted. Pull request 5 takes every such row of today's base, as `tests/policy-redundancy-probe.sh` lists them, into the new base unchanged, where the prune has not already produced it, unless its body deletes one deliberately, saying so and proving both directions as AGENTS.md asks; `tests/integration/filesystem_policy.sh` pins the `/usr/bin` case before and after.

## A.5 The mapping table

"Refuse" always means `refuse_cfg` with `PHB-EPOLICY`, the file, the line of the offending value, and the Ares field path. "Notice" means one line through `_log` on standard error, which is always printed, so nothing is dropped silently; notices are collected into the summary line of A.7.

### A.5.1 Root and supervised code

| Ares element | Phobos concept | Translation | What is refused |
| --- | --- | --- | --- |
| `thisPolicyFileCompliesToThePolicyVersion` | none, a format gate | Must be `int` `1`. | Absent, not an `int`, or any other value. |
| unknown key at any level | none | none | Always refused, as Ares refuses it. |
| `theFollowingProgrammingLanguageConfigurationIsUsed` | the programming language configuration file of A.4.2, and through it the base policies and the placeholders | Must be a non-empty `str` of the form `[A-Z][A-Z0-9_]*`. Sets `PARSED_ARES_CONFIGURATION` to it. The file `language-configurations/<value>.cfg` must exist; it decides which bases the run folds (A.6) and how placeholders are determined (A.5.2 step 4). The parts of the name (build tool, analyser, weaving) mean nothing to Phobos and grant nothing: an agent jar, an AspectJ weaver or a Maven repository is reachable only if the base or an explicit entry grants it. | Absent, not a `str`, a value of another shape, a value with no configuration file, and two Ares files in one run naming different configurations (one run has one base and one set of placeholder values). |
| `theSupervisedCodeUsesTheFollowingPackage` | none (a JVM concept) | Checked to be absent, `null` or a non-empty `str`; no grant. | Any other type, or an empty string. |
| `theMainClassInsideThisPackageIs` | none | As above. | As above. |
| `theFollowingClassesAreTestClasses` | none: Phobos confines the whole process, test classes included | Checked to be a `seq` of non-empty `str`. Notice: "test classes get no exemption from Phobos; what they need must come from the base or from an explicit entry". | Absent, not a `seq`, or an item that is not a non-empty `str`. |
| `theFollowingTestBehaviorIsConfigured` | none | Absent or an empty `map`. | `null` or any key inside it (Ares defines none). |
| `theFollowingResourceAccessesArePermitted` | the exercise allow-list | A `map` with exactly the six list keys, each a `seq`. | A missing list, an extra key, a list that is not a `seq`. |

The patterns Ares applies to package, class and thread names (`\p{javaJavaIdentifierStart}` and friends) are not re-implemented (decision Q11): they are rules of one programming language, Phobos stays independent of every language, those fields grant nothing at the operating-system level, and Ares refuses a bad value itself when it loads the same file.

What Phobos checks, stated narrowly: the structure and the type of every field of the schema, and the value of every field it maps (the language, the file system, network and timeout fields). For the fields it does not map (package, main class, test classes, commands, thread and package entries) it checks structure, type and non-emptiness only, so it can accept a value there that Ares refuses; such a value grants nothing in Phobos, and Ares refuses the file when it loads it. Placeholders are expanded only in `onThisPathAndAllPathsBelow`. A `${` in the package, main class, test class, thread class, package import or host field is refused: Phobos does not expand placeholders there, and refusing is the conservative answer (with the default system properties every expansion contains a `/`, which none of those fields' patterns admits, so Ares refuses such a value as well, but an overridden property could expand differently). A `${` in a command is left alone, since commands grant nothing here.

### A.5.2 File system: `regardingFileSystemInteractions[i]`

| Ares field | Phobos section | Landlock rights | Notes |
| --- | --- | --- | --- |
| `readAllFiles: true` | `[read]` | READ_FILE, READ_DIR | |
| `overwriteAllFiles: true` | `[write]` | WRITE_FILE, TRUNCATE | Ares: "replacing the contents of existing files". |
| `createAllFiles: true` | `[create]` and `[create-symlink]` | MAKE_REG, MAKE_DIR, MAKE_SYM | Ares counts `createFile`, `createDirectory`, `createDirectories`, `createTempFile`, `createTempDirectory` and `createSymbolicLink` as create, so both sections hold exactly what Ares permits. `createLink` (a hard link) needs REFER across directories, which only the row below grants. |
| `executeAllFiles: true` | `[execute]` | EXECUTE | |
| `deleteAllFiles: true` | `[delete]` | REMOVE_FILE, REMOVE_DIR | |
| `createAllFiles: true` and `deleteAllFiles: true` together | `[restructure]` as well | MAKE_REG, MAKE_DIR, REMOVE_FILE, REMOVE_DIR, REFER | Decision Q9: an entry that may both create and delete may move, as Ares lets `Files.move` do. REFER is what a move or a hard link across directories needs; Landlock checks it on both the source and the destination, so a move only works between two trees that both hold it. |
| all five `false` | none | none | Ares's `createRestrictive(path)`; grants nothing in Ares either. No row is written. |
| never produced | `[create-ipc]` | | Ares has no right for UNIX sockets or named pipes. |

`onThisPathAndAllPathsBelow` is turned into one absolute path, in this order, and refused at the first step that fails:

1. Must be a non-empty `str`.
2. `*` is refused: it would grant the rights on `/`, the whole file system, which a `.cfg` can say explicitly if it is really meant.
3. A backslash is refused (Ares treats it as a separator on Windows; on Linux it is part of a name).
4. Placeholders: `${PROJECT_ROOT}` is replaced by the project root (step 6). Every other `${name}` is replaced by the value the programming language configuration determines for `name` (A.4.2, decision Q3), so `${java.home}`, `${user.home}` and `${java.io.tmpdir}` work for the Java configurations without Phobos knowing what they mean. A placeholder the configuration does not name, an unterminated `${`, and a value the configuration cannot determine are refused, naming the placeholder and the configuration file.
5. A `..` segment is refused, as Ares refuses it.
6. A relative path is made absolute against the project root, and `${PROJECT_ROOT}` (step 4) is replaced by the same directory. **Phobos's rule, and the only one** (decision Q2): the project root is the value of `--project-root` where the operator gave one, which must be an absolute path to an existing directory or is refused; otherwise the value of the last `--chdir` in the tail flags, which is the directory `phobos-landlock-filesystem-and-networksystem` changes into before it runs the command (`TailPhobos.cfg` ships `--chdir /var/tmp/testing-dir`); otherwise there is none. When there is none, or the last `--chdir` is relative, a relative path and `${PROJECT_ROOT}` are refused ("this run has no project root to resolve 'allowed.txt' against; give --project-root, or write the absolute path"); an absolute path without `${PROJECT_ROOT}` is unaffected. Phobos never falls back to the policy file's parent directory, never to the current directory of the command, and never to the current directory of the process that runs `phobos.sh`.

   Why these two sources, and why not the fallback Ares has. In Ares, a relative path is resolved by the JVM against its working directory (`Path.toAbsolutePath()`), and `${PROJECT_ROOT}` is the root its reader is given. Ares's reader falls back to the policy file's parent directory only when it is given no root, and its two callers always give one: `JupiterSecurityExtension` with `projectFolderPath(Path.of("").toAbsolutePath())` and `SecurityPolicyReader.selectSecurityPolicyReader(path)` with `Path.of("").toAbsolutePath()`, the test JVM's working directory. So in practice both mean the directory the build tool starts the test JVM in, which for Gradle's `Test` task and Maven Surefire is the project directory by default. Phobos cannot see that directory, so it takes the operator's statement of it; the policy file's parent is not that statement, since the file comes from the instructor's test repository (A.8) and where it lies says nothing about where the build runs.

   This is an integration requirement, stated in the documentation and in SECURITY.md: the project root, `--project-root` or else the tail's last `--chdir`, must be the directory the build tool starts the test JVM in. A grading command that changes directory before it starts the build (`bash -c 'cd sub && ./gradlew test'`) breaks the tail-flag source, and then a relative Ares path names one file to Ares and another to Phobos; `--project-root` exists for that operator, and for one whose tail flags fix no directory. Both sources are operator input fixed before the command starts, which a submission cannot change, so a mismatch is a misconfiguration, not an attack path, and the import resolves nothing at run time. `--project-root` is passed from `phobos.sh` to `phobos-policysystem.sh` and affects nothing but the import; the project root a run used, and which of the two sources gave it, is written to the debug log. A suite pins the order: `--project-root`, else the last `--chdir`, else refused, and nothing else.
7. The resulting line goes through the existing `refuse_relative_path`, `refuse_wildcard_path` and, because an Ares policy is always an exercise configuration, `refuse_missing_path` for `[read]` and `[execute]`.
8. New for imports: the path must exist in every section, `[write]`, `[create]` and `[delete]` included. Ares does not say whether a path is a file or a directory, and the filesystem layer materialises a missing changeable path as an empty file (`materialise_write_path`), which for a path such as `target` would break the build that was meant to create a directory there. Decision Q10: refused, never materialised.

9. Before a (section, path) row is written, the covered-entry skip of A.6 decides whether the base already grants it; a covered row is counted and not written.

### A.5.3 Network: `regardingNetworkConnections[i]`

| `openConnections`, `sendData`, `receiveData` | Translation |
| --- | --- |
| all `true` | Two `[connect]` rules, one for TCP and one for UDP (`... udp`), built as below (decision Q6). |
| all `false` | No rule (Ares's `createRestrictive(host, port)`). |
| any other combination | Refused. Phobos cannot let a connection be opened and forbid sending or receiving on it (config_doc.txt: "There is no `openConnections` / `sendData` / `receiveData` toggle"), and `openConnections: false` with `sendData: true` is Ares's unconnected datagram send, which Phobos would need a `udp` rule for. Granting the connection would permit more than the policy states; granting nothing would narrow without saying so. Decision Q5: refused. |

`onTheHost` and `onThePort` become an `allow` line, which is then handed to the existing `append_connect_rule`, so the address checks, the wildcard refusal and the port checks of a `.cfg` line apply unchanged and the merged-policy check `refuse_unenforceable_network_rules` judges it with every other rule:

| Ares host | `onThePort` 1..65535 | `onThePort` 0 (every port) |
| --- | --- | --- |
| `localhost` | `allow localhost:<p>` | `allow localhost` |
| IPv4 literal | `allow <a>:<p>` | `allow <a>:*`, which the merged-policy check accepts only for loopback and refuses otherwise |
| IPv6 literal, IPv4-mapped included | `allow [<a>]:<p>` | `allow [<a>]`, as above |
| DNS name | `allow <name>:<p>`, enforced by name by the egress broker; the network layer refuses it when no `--resolver` is given, as for a `.cfg` | refused: a host other than loopback must name a port |
| DNS name ending in `.` | refused with a hint to drop the dot (decision Q13) | refused |
| `*` | `allow *:<p>`, every host on that port, plus a notice naming it | refused |
| anything else | refused (Ares's `HOST_PATTERN` admits nothing else, so this is a backstop) | refused |

`onThePort` must be an `int` from 0 to 65535. Ares's `connect` covers both `java.net.Socket` and `java.net.DatagramSocket`, so every granted entry becomes a TCP rule and the same rule with the `udp` marker (decision Q6), each handed to `append_connect_rule`. What that brings with it, all of it existing Phobos behaviour:

- **What the code does with a `udp` rule today**, read from the code rather than from its documentation. `emit_connect_port_args` in `core/phobos-tools-networksystem/phobos-network-args.sh` hands a `udp` rule that names a port to the enforcer as `--connect-udp <port>`, unless the merged policy also holds a `udp` loopback rule with no port: then it emits no `--connect-udp` at all, the Landlock UDP connect layer stays off for the run, and the connect guard alone enforces every `udp` rule, by host and port (PR 159). A `--connect-udp` rule needs Landlock version 10 (Linux 7.2). On an older kernel `detect_landlock_version` in `core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.c` refuses before the command starts, with status 125 (`EXIT_CODE_POLICY_ERROR`, which is `PHB_ENFORCER_REFUSED_EXIT` in `phobos-constants.sh`) and the line `[phobos-landlock-filesystem-and-networksystem] UDP network rules require Landlock version 10`; the protection matrix pins that status and that line (`network.sh`, `policy-syntax.sh`). `config_doc.txt` calls this refusal `PHB-EPOLICY`, which is status 11; the code and the matrix say 125. A `udp` loopback rule with no port needs no Landlock rule and runs on any kernel.
- **Decision R1: the programming language configuration adds `allow localhost udp` to its base** (A.4.2, `[connect]`). Without it, the shipped Java base has TCP loopback rules only, so on the kernels the CI runners and Docker Desktop have today (6.17 and 7.0) an Ares policy with a granted network entry that names a port would be refused with status 125. With it, every run that imports an Ares policy has a `udp` loopback wildcard in its merged policy, and that has three consequences, each existing behaviour of the network layer:
  1. **This now permits a submission graded under an imported Ares policy to send UDP datagrams to every port of every loopback address (127.0.0.0/8 and `::1`, which is what the connect guard holds the name `localhost` to), which it did not permit before.** Before, the Java base had no `udp` rule, and the guard refused every datagram. It does not reach any other address: the guard still refuses a datagram to a host no `udp` rule names, on every port.
  2. An Ares policy whose granted entry names a port runs on a kernel below Landlock version 10 instead of being refused with 125: its `udp` rules are enforced by the connect guard alone, by host and port, on every kernel. A `.cfg`-only run is unchanged and is still refused with 125 there for a `udp` rule that names a port, since it never loads a language configuration.
  3. On a version 10 kernel the imported `udp` rules lose Landlock's port check as a second line of defence and keep the guard's host and port check, which is what the shipped Java base's TCP loopback wildcards already do to every TCP rule. The guard performs every datagram connect and send itself from its own copy of the address (PR 145), so the destination cannot be swapped after its check.
  UDP bind is unchanged: Ares produces no `[bind]` row, and the base's `allow 0 udp` is the ephemeral grant, which never refuses an old kernel. Pull request 4 states consequence 1 in its body in exactly those words.
- A `udp` rule that names a DNS name is resolved once, before the command starts, through `--resolver`, and held to the addresses it had then; without `--resolver` the run is refused (`PHB-ERUNTIME`).
- A `udp` rule brings the ephemeral UDP bind grant (`--ephemeral-bind-udp`) with it, as every `udp` `[connect]` rule does; the configuration's `allow localhost udp` is such a rule, and the Java base's `allow 0 udp` already grants it.

`[bind]` and `[accept]` are never produced: Ares 2 has no listening permission. The base's `[bind]` rows (`allow 0`, `allow 0 udp` in the Java base) stay as they are.

### A.5.4 Domains with no Phobos equivalent

| Ares domain | Why there is no equivalent | Treatment |
| --- | --- | --- |
| `regardingCommandExecutions` | Landlock grants execution by path, not by command name and arguments; the base already grants `x` on `/usr` and `/bin`. Ares documents that this domain "has no Phobos section". | Structure checked (a non-empty `str`, or a `map` with exactly `executeTheCommand` as a non-empty `str` and `withTheseArguments` as a `seq` of non-empty `str`). No grant, no PATH lookup. One notice with the count. A command whose binary the base does not grant fails with EACCES, visibly. |
| `regardingThreadCreations` | Threads are counted per class in Ares; the only OS knob is `RLIMIT_NPROC`, which counts every thread of the user, the JVM's own included. | Structure checked (`createTheFollowingNumberOfThreads` an `int`, `ofThisClass` a non-empty `str`). No limit written. Notice. |
| `regardingPackageImports` | A JVM concept. | Structure checked (`importTheFollowingPackage` a non-empty `str`). Notice. |
| test classes, package, main class | JVM concepts. | See A.5.1. |

### A.5.5 Timeouts: `regardingTimeouts[i].timeout`

- Each value must be an `int` of at least 1 (Ares refuses 0 and negatives).
- Within one Ares file, the tightest value wins, as `JavaResourceLimitsExtractor.getTightestTimeout` and `collectResourceLimits` compute it. The comparison is done on digit strings (length, then lexical order), so no value can overflow the shell's arithmetic.
- The winner is converted from milliseconds to Phobos's seconds-with-three-decimals exactly, by moving the decimal point: `120000` becomes `120.000`, `1500` becomes `1.500`, `1` becomes `0.001`. It is never rounded: a rounding of `500` to `0` would switch the timeout off, which is the widest possible result.
- The converted value goes through the existing `set_parsed_timeout`, which refuses more than 15 digits of seconds (so `Long.MAX_VALUE` ms is refused with the existing message).
- Across files, the existing merge applies unchanged: the largest value any configuration names wins, and a zero disables. An Ares file can never write zero.
- An empty `regardingTimeouts` list writes no timeout, matching Ares's own Phobos writer (`collectResourceLimits` returns an empty map), with a notice; the default of 600 seconds then applies, unless another configuration names one.
- Decision Q4: the timeout is imported although Ares means it for the supervised code and Phobos bounds the whole build with it. A policy written for Ares with `timeout: 3000` therefore ends a Gradle build after 3 s; the summary line names the imported timeout, and the documentation says so beside the mapping table.
- `mem_mb`, `nproc`, `nofile`, `fsize_mb` and `cpu` are never produced; their defaults and the base apply.

## A.6 Composition with the additive merge and the base

- `fold_cfg_into` calls `parse_ares_policy` instead of `parse_cfg_policy` for a `.yaml` or `.yml` file and then runs the same `fs_union_dir`, `net_union` and `merge_limits`. The file counts as an exercise configuration everywhere, so a run given only an Ares policy keeps its network rules (the "no `--config`" most restrictive shape is unchanged and still keyed on the number of `--config` files).
- **Base selection.** Before it folds any base, `phobos-policysystem.sh` reads the configuration name of every `.yaml`/`.yml` `--config` file (with the YAML reader, so a malformed file is refused at this point already) and loads its programming language configuration file. When there is none, the bases are every `Base*.cfg` beside the script, exactly as today. When there is one, the bases are exactly the files its `[base]` names, in the order written, and no other `Base*.cfg` is folded; a named base that does not exist is refused. From pull request 4 on, the configuration's `[connect]` rows (A.4.2) are folded into the base after those files, as one more base `[connect]` section. Two Ares files that name different configurations are refused, even where their `[base]` lists agree, since one run has one base and one set of placeholder values. This is the only change to base discovery. It is a deliberate change of base chosen by data, not a guaranteed narrowing: a configuration that names a top-level base folds a subset of what a `.cfg`-only run folds plus its own `[connect]` rows (`allow localhost udp`, decision R1), and one that names a base under `language-configurations/bases/` (the Maven base of pull request 7) folds grants that no `.cfg`-only run in the same image gets. The pull request that ships such a base or such a row states what it permits, in the words AGENTS.md asks for. What base selection can never do is add a base the configuration does not name, or let a `.cfg`-only run reach a base under `language-configurations/` or a configuration's `[connect]` rows.
- **Covered-entry elision.** `resolve_rights_hierarchy` refuses an entry whose rights are a strict subset of an ancestor's, because a `.cfg` author who writes that expects a narrowing that Landlock cannot hold. A typical Ares policy is exactly that shape: `allowed.txt` with `r`, beneath the base's `/var/tmp/testing-dir` with `rx`. Refusing it would make the import unusable for the common case, and it is not a mistaken narrowing in Ares's own semantics, where entries are unioned just as Landlock unions rules. So the importer itself does not write such a row. It never edits a merged file: the decision is taken inside `parse_ares_policy`, row by row, before the row exists, against the folded base only (`base_dir` in `phobos-policysystem.sh`, complete before any exercise configuration is folded). `ares_row_covered_by_base <section> <path> <base_dir>` answers yes when, and only when, the base's file for that same section holds a path that exists and that, **after both are resolved through their symbolic links** with `resolve_symlinks`, is the imported path itself or a strict ancestor of it. Consequences:
  1. Base rows and `.cfg` rows are never touched, because nothing merged is edited (AGENTS.md: "A base entry an ancestor already covers is not dead code").
  2. The comparison is on resolved paths, which is how the filesystem layer folds targets. A lexical comparison would be wrong: `/proj/link/x` with `/proj/link -> /elsewhere` is lexically under `/proj` but Landlock anchors the rule on `/elsewhere/x`, which the base does not cover, so skipping it would take away a right the policy grants, a silent narrowing. The resolved comparison writes that row. A base path that does not exist is not an ancestor, since the filesystem layer drops a missing `[read]` or `[execute]` path.
  3. The result does not depend on the order of the `--config` files, because only the base is consulted. A row covered only by an ancestor that another exercise `.cfg` adds is written, and then meets the existing strict-subset refusal, which fails closed.
  4. With the resolved comparison a skip is exactly neutral for Landlock, which unions every rule along a path; with any doubt (a resolution that fails, a path that does not exist) the row is written, which can only lead to the existing refusal.
  The number of skipped rows is reported in the summary line, worded so that it says what it means: "N entries of '<file>' are already covered by the base policy; Phobos adds nothing for them, and the narrower intent of those entries is enforced by Ares inside the JVM, not by Phobos".
- Network rules are deduplicated by `net_union` as today; an Ares `localhost` rule beside the base's `allow localhost` collapses into one.
- Timeouts: A.5.5.

## A.7 Error messages

Every refusal goes through `refuse_cfg`, with `PARSE_LOCATION` set to the YAML file and the line of the offending value. The text names the Ares field path, says what is wrong and what to write instead. Examples (exact wording is pinned by the unit suites):

```
Policy invalid: regardingNetworkConnections[1] grants openConnections but not sendData, and Phobos cannot let a connection be opened while forbidding sending on it; grant all three or none. Found in 'security-policy.yaml', line 31. (PHB-EPOLICY)
Policy invalid: regardingFileSystemInteractions[0].onThisPathAndAllPathsBelow '*' would grant these rights on the whole file system; name the directory instead. Found in 'security-policy.yaml', line 14. (PHB-EPOLICY)
Policy invalid: regardingTimeouts[0].timeout '0' must be a whole number of milliseconds of at least 1. Found in 'security-policy.yaml', line 52. (PHB-EPOLICY)
Policy invalid: 'yes' is read as a boolean by some YAML readers and as a string by others; write true or false. Found in 'security-policy.yaml', line 18. (PHB-EPOLICY)
Policy invalid: the key 'readAllFiles' appears twice in this mapping, first on line 15. Found in 'security-policy.yaml', line 17. (PHB-EPOLICY)
Policy invalid: the programming language configuration 'JAVA_USING_MAVEN_WALA_AND_ASPECTJ' has no file 'language-configurations/JAVA_USING_MAVEN_WALA_AND_ASPECTJ.cfg' beside phobos-policysystem.sh, so Phobos does not know which base policy it runs under. Found in 'security-policy.yaml', line 3. (PHB-EPOLICY)
Policy invalid: ${java.home} cannot be determined: 'command-ancestor java 2' found no command 'java' on the PATH. Found in 'language-configurations/JAVA_USING_GRADLE_WALA_AND_ASPECTJ.cfg', line 6. (PHB-EPOLICY)
```

One summary line per imported file, always printed through `_log`:

```
Ares 2 policy 'security-policy.yaml' (JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ): 3 file system rows and 1 network entry imported as a TCP and a UDP rule; 2 entries already covered by the base, whose narrower intent Ares enforces in the JVM; not enforced by Phobos: 1 command, 0 thread and 2 package entries, and the test-class exemption.
```

## A.8 Security analysis

- **Nothing is permitted that the policy does not state.** Every grant comes from a field set to `true`, mapped to the right that field names in Ares. Three translations grant a right beyond the literal field name, each because Ares's own semantics include it, and each pull request introducing one says "this now permits X, which it did not permit before":
  - `createAllFiles` adds `[create-symlink]`, since Ares's create category includes `createSymbolicLink`;
  - `createAllFiles` with `deleteAllFiles` adds `[restructure]`, so REFER, since Ares lets such an entry move files (decision Q9);
  - a granted network entry adds a `udp` rule beside the TCP rule, since Ares's connect covers datagram sockets (decision Q6).
- **One grant comes from the programming language configuration, not from the policy.** `allow localhost udp` (decision R1, A.4.2 and A.5.3) is folded into the base of every run that imports an Ares policy, whatever the policy says: this now permits such a run to send UDP datagrams to every port of every loopback address, which it did not permit before. It is data in the configuration file, never code, and a `.cfg`-only run never gets it. A configuration can add nothing beyond loopback this way, because its `[connect]` section refuses every rule but a loopback rule without a port (A.4.2). Pull request 4 states it in those words.
- **Nothing the policy permits is dropped without a word.** Every narrowing (no exemption for test classes, unmapped domains, an empty timeout list) produces a notice and is documented. Every combination Phobos could only approximate is refused.
- **No guessed translation.** `*` paths, `*` with port 0, a non-loopback host with port 0, partial network flags, unknown placeholders, a relative path or `${PROJECT_ROOT}` with no project root, a missing path, and every ambiguous YAML scalar are refused.
- **Same checks as a `.cfg`.** Translated lines go through `refuse_relative_path`, `refuse_wildcard_path`, `refuse_missing_path`, `append_connect_rule` (with `refuse_wildcard_host_name`, `refuse_malformed_address`, `refuse_unusable_port`), `set_parsed_timeout`, `refuse_unenforceable_network_rules` and the filesystem layer's `resolve_rights_hierarchy`. The importer adds checks; it removes none.
- **The covered-entry skip cannot widen.** It only leaves out an imported row whose right on that path the base already grants on the same resolved target or a resolved ancestor; it never adds a row and never edits a merged file, so no base or `.cfg` row can be lost.
- **Narrowness inside the base is not enforced by Phobos.** That is the additive model, unchanged; the summary line says so for each file, and the documentation states it next to the mapping table.
- **Trusted input.** An Ares policy grants access exactly as an exercise `.cfg` does, so SECURITY.md's integration requirement extends to it: the file given to `--config` must come from the instructor's test repository, never from the student's assignment tree, which a submission controls. In Artemis builds a `security-policy.yaml` usually sits in the test repository's `src/test/resources`; a grading script that searches the merged working tree for it could pick a student's copy. SECURITY.md gains this sentence.
- **No new attack surface in the image.** No package or interpreter is added; the reader is bash already present.
- **Placeholders and the project root are operator input.** Their values come from the environment `phobos.sh` was started in, the image, the programming language configuration, the `--project-root` flag and the tail flags, all set before the command runs and out of the submission's reach; each must be an absolute, existing directory, and each is written to the debug log.
- **The UDP floor is part of the import, not a later caveat.** Every granted network entry becomes a `udp` rule as well (decision Q6). A `udp` rule that names a port needs Landlock version 10 unless a `udp` loopback rule with no port sits beside it, and below version 10 the enforcer otherwise refuses the run with status 125 (A.5.3, verified in the code). Decision R1 puts that loopback rule into every programming language configuration, so an Ares run always has it: the Landlock UDP connect layer then stays off for the run on every kernel, and the connect guard alone enforces each imported `udp` rule by host and port, as it already does for the TCP rules beside the Java base's TCP loopback wildcards. On a version 10 kernel that gives up Landlock's port check as a second line for those rules; below version 10 it lets the run start at all. The import never drops the `udp` rule to make a run start, and never writes it only where the kernel happens to support it: the specification does not depend on the kernel.
- **Base selection follows the data and nothing else.** A run with an Ares policy folds exactly the bases its configuration names, and its `[connect]` rows. For a top-level base that is a subset of what a `.cfg`-only run folds, plus `allow localhost udp`; for a base under `language-configurations/bases/` it is a different base, whose grants the pull request shipping it states explicitly. A `.cfg`-only run never reaches a base under `language-configurations/` nor a configuration's `[connect]` rows.
- **No language in the code.** The loader and the importer contain no language name; a reviewer checks every pull request of this plan for it, and a test greps the scripts under `core/` (the data folder `core/config/` excepted) for `JAVA_USING`, `java.home`, `user.home` and `java.io.tmpdir` to prove it. Examples and comments elsewhere in the core may keep naming Gradle, as they do today; logic may not.
- **Parser divergence.** The subset refuses every construct whose meaning differs between YAML readers, so where Phobos and Ares could disagree on a value, Phobos refuses; for every field Phobos maps, it can be stricter than Ares, never laxer. For the fields it does not map it checks less than Ares (A.5.1), which cannot widen anything, since they grant nothing.

## A.9 Tests, both directions

| Level | Suite | Permitted direction | Forbidden direction |
| --- | --- | --- | --- |
| Unit | `tests/unit/phobos-tools-policysystem/yaml_subset.sh` (new) | every accepted construct of A.4.1 produces the exact records, both sequence indentations, `[ ]`, `{}`, both quote styles, comments | every refused construct produces `PHB-EPOLICY` with the right line: anchors, aliases, tags, block scalars, flow items, multi-documents, duplicates, tabs, CR, BOM, NUL, ambiguous booleans and numbers, bad escapes, continuation lines |
| Unit | `tests/unit/phobos-tools-policysystem/ares_policy.sh` (new) | the documented example policy and the two example policies of the Ares repository (rewritten as fixtures here, not copied) produce the expected `.paths`, `net.rules` and timeout; each field of A.5 maps as the table says; ms conversion of 1, 999, 1000, 1500, 120000, the 15-digit-seconds boundary | each "refused" cell of A.5 is refused with its message; a policy that would map to nothing but notices still parses |
| Integration | `tests/integration/ares_policy_program.sh` (new, a step in `test.yml`) | `phobos-policysystem.sh --config x.yaml` writes the specification; the result equals a hand-written `.cfg` with the same meaning; the covered-entry skip lets `allowed.txt` under the base's project tree pass; a `.cfg` and a `.yaml` given together merge additively, with the same result in either order; timeout min within a file, max across files | the skip never removes a base row (the `/usr/bin` case of `filesystem_policy.sh`), never skips a row whose ancestor is only lexical (a symbolic link fixture) or missing, a relative path is never resolved against the current directory of the caller or of the policy file (run from another directory, with neither `--project-root` nor a tail `--chdir`, it is refused), a misnamed file is refused by both readers, a strict-subset `.cfg` row is still refused when an Ares file is present |
| Integration | `tests/integration/malformed_cfg.sh` (extended) | | the file-level refusals (unreadable, BOM, NUL, CR, invalid UTF-8) for a `.yaml` name, with the same messages |
| Unit | `tests/unit/phobos-tools-policysystem/language_configuration.sh` (new) | a configuration file with `[base]` and the four primitives loads; `environment` with and without fallback, `command-ancestor` through a chain of symbolic links, `fixed`, `password-database home` giving the password database's home with `HOME` changed; a `[base]` entry with a slash resolves under `language-configurations/`; from pull request 4, a `[connect]` section with `allow localhost udp` loads into the rows `append_connect_rule` writes for it | an unknown section or primitive, a value that is not an absolute existing directory, a command not on the `PATH`, a password database with no entry for the uid or an empty, relative or control-character home field, a `[base]` entry with `..`, a missing file, CR, BOM and NUL are refused with file and line; from pull request 4, a malformed `[connect]` line (a wildcard host name, port 0, an unknown transport) is refused with the `.cfg` message, file and line, and so is every well-formed line that is not a loopback rule without a port (`allow 127.0.0.1:53 udp`, `allow 10.0.0.1:53 udp`, `allow example.org:443`, `allow *:53 udp`) |
| Integration | `tests/integration/ares_policy_program.sh` (more cases) | a policy naming a configuration folds only its `[base]`, while a `.cfg`-only run in the same core still folds every `Base*.cfg`; `${java.home}` in a path resolves to the directory the configuration determines; `--project-root` overrides the tail's `--chdir` for relative paths and `${PROJECT_ROOT}`; `createAllFiles` with `deleteAllFiles` writes `[restructure]`; a granted network entry writes a TCP and a `udp` rule; from pull request 4, the specification of an Ares run holds the configuration's `localhost * udp` row | two Ares files naming different configurations (also with the same `[base]`), a configuration with no file, a `--project-root` that is relative or missing, a placeholder the configuration does not name; the specification of a `.cfg`-only run in the same core holds no `udp` row, since no configuration was loaded |
| Unit | `tests/unit/phobos-tools-policysystem/no_language_in_code.sh` (new) | | no script under `core/` outside `core/config/` contains `JAVA_USING`, `java.home`, `user.home` or `java.io.tmpdir` |
| Matrix | `tests/integration/protection-matrix/policy-syntax.sh` (extended) | every accepted Ares shape is accepted with status 0 | every refused Ares shape is refused with status 11 |
| Matrix | `tests/integration/protection-matrix/filesystem.sh` (extended) | a path granted only by an imported `readAllFiles` is readable, one granted `overwriteAllFiles` is writable | a sibling path the import does not name is denied, a file under an `executeAllFiles: false` entry is not executable, an all-false entry grants nothing, with the usual unprotected control and layer-off run |
| Matrix | `tests/integration/protection-matrix/network.sh` (extended) | under the shipped `JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ.cfg`, whose `BaseLanguage-java.cfg` the matrix replaces with its minimal base (`pm_install_base`), so the configuration's `allow localhost udp` is the only `udp` rule beside the import: an imported loopback entry with a concrete port connects over TCP, and a datagram to that port goes on every kernel, those below Landlock version 10 included (the command starts, no status 125), with the network layer's log saying the connect guard alone enforces the `udp` port; a datagram to another port of `127.0.0.1` and to `127.0.0.2` goes too, which pins the R1 widening so that it stays visible; an imported entry for `10.0.0.1` with that port lets a datagram there pass the guard and meet the missing network (`ENETUNREACH`, the control pattern of `network-edge.sh`) | a TCP connect to another port of the same host is refused, since the minimal base has no TCP loopback wildcard; a datagram to `192.0.2.1` and to `10.0.0.1` on another port is refused by the guard with `EACCES`, not `ENETUNREACH`, so it is the sandbox that refuses it; a `.cfg`-only run with `allow 127.0.0.1:<port> udp` is still refused below version 10 with status 125 and the enforcer's line, the existing check, unchanged; each with control and layer-off run |
| Matrix | `tests/integration/protection-matrix/timeout.sh` (extended) | a 1500 ms Ares timeout ends a sleeping run at 1.5 s, not at 1 s or 2 s | |

## A.10 Documentation

- `README.md`, "Configuration format": a new subsection "Ares 2 policy files" with how detection works, the mapping table of A.5 in short form, the refusals, the narrowings and the "Phobos adds, Ares narrows" sentence.
- `core/phobos-tools-policysystem/config_doc.txt`: a fourth chapter, "4. What an Ares 2 policy becomes", with the full mapping of A.5.
- `core/phobos-policysystem.sh` and `core/phobos.sh` `--help`: one paragraph under `--config` on the extension rule.
- `SECURITY.md`: the trusted-input sentence of A.8.
- `CLAUDE.md` and `README.md` project structure: the three new files under `phobos-tools-policysystem/` and the folder `core/config/language-configurations/`.
- `README.md` and `--help`: `--project-root`, and the programming language configuration files, with the four primitives and, from pull request 4, the `[connect]` section and its `allow localhost udp` (decision R1), as the one place where a language enters Phobos.
- `tests/README.md`: the new suites and the extended ones.
- If pull request #122 (Docusaurus) has merged by then: a page `documentation/docs/user/policy-reference/ares-2-policy.md` beside the section pages, and a cookbook entry; otherwise the README is the reference and the page is a follow-up.

## A.11 Pull requests, in order

Pull requests 1 to 4 form one stack and pull requests 5 and 6 a second, based on `main`; pull requests 7 and 8 come after both. Per AGENTS.md, a stacked pull request gets its workflows started with `workflow_dispatch`.

1. **`feature/ares2-yaml-subset-reader`**: `phobos-policy-yaml.sh` and `yaml_subset.sh`, with the strict UTF-8 check, sourced but not yet called. A pure function with a complete test table. No behaviour change.
2. **`feature/ares2-language-configurations`**: `phobos-language-configuration.sh`, the four primitives, the four `GRADLE` configuration files naming `BaseLanguage-java.cfg`, the lines in the run-phase Dockerfile and `assemble-run-phase-context.sh` that ship the folder, `language_configuration.sh` and `no_language_in_code.sh`. Loaded but not yet used. No behaviour change.
3. **`feature/ares2-policy-filesystem-and-timeout`**: `phobos-policy-ares.sh` with the whole schema check, the configuration lookup, base selection, placeholders, `--project-root`, the file system and timeout mappings (`[create-symlink]` and `[restructure]` included), the unmapped-domain notices, the covered-entry skip, the extension dispatch in `fold_cfg_into`, and a refusal of any non-empty `regardingNetworkConnections` ("not yet imported"), so the intermediate state fails closed. Unit, integration and matrix tests for those domains; README, `config_doc.txt`, `--help`, SECURITY.md. The body states what it now permits (symbolic links and moves under an imported `createAllFiles`).
4. **`feature/ares2-policy-network`**: the network mapping of A.5.3, TCP and UDP, replaces the interim refusal; the `[connect]` section of the programming language configuration (A.4.2), `allow localhost udp` in the four `GRADLE` files, and its fold into the base (A.6), which together are decision R1; matrix `network.sh` additions; documentation extended. The body states that an imported network entry now permits UDP as well, and, in exactly these words, "this now permits a submission graded under an imported Ares policy to send UDP datagrams to every port of every loopback address, which it did not permit before".
5. **`feature/run-phase-image-java25`**, based on `main`, independent of pull requests 1 to 4, and opened once the prune plan's pull request 8 has merged, because it adopts a base that plan's pruner produces (decision R4, A.4.4): both stages of `docker/run_phase/java/Dockerfile` move from `ls1tum/artemis-maven-template:java17-25` to `ls1tum/artemis-maven-template:java25-1`, pinned by its multi-architecture index digest (A.4.3); the Gradle reference exercise and its `gradle-repository` stage and manifest; and `core/config/BaseLanguage-java.cfg` re-pruned on JDK 25 from that exercise, with the base entries an ancestor covers carried over (A.4.4). The run-phase job of `build.yml` holds the image to every acceptance suite on both architectures. The body lists every widening and every narrowing of the Java base, and the `Breaking changes and migration` section says that every run now uses JDK 25, Maven 3.9.16 and Gradle 9.8.0, so a Gradle exercise whose wrapper names a Gradle before 9.1.0 cannot run, and one without the four settings of A.4.4 forks a daemon that the group lock refuses.
6. **`feature/ares2-maven-reference-exercise`**, stacked on pull request 5: the Maven reference exercise of A.4.3 under `var/tmp/testing-dir/java-maven/maven-reference/`; the `maven-repository` stage of the run-phase Dockerfile and its manifest `docker/run_phase/java/maven-repository.sha256`, which pre-load the jars the exercise needs into the run-phase image and so into the prune image built from it; the exercise and the manifest in `assemble-run-phase-context.sh`; and the two sentences in CLAUDE.md and AGENTS.md that call the template checker the only Java here. Nothing a policy permits changes, since no shipped base grants `/root/.m2`. It lands before the prune plan's Task 14.1, which consumes it.
7. **`feature/ares2-maven-base`**: the base the prune plan's pruner produced from that exercise (prune plan Task 14.1), adopted as `language-configurations/bases/BaseLanguage-java-maven.cfg`, and a `MAVEN` configuration file naming it for each configuration name whose run passes (A.4.3), each with the same `[placeholders]` and `[connect]` as the `GRADLE` ones. Needs pull requests 4 and 6 of this plan and pull request 14 of the prune plan merged first. The body lists every grant of the base as "this now permits X, which it did not permit before" for a run under a `MAVEN` configuration, and attaches the pruner's record.
8. **`feature/ares2-policy-docs-site`** (only if #122 has merged): the Docusaurus page and cookbook entry.

Ordering against the prune plan (pull request 162), stated once here and mirrored there: the prune plan's pull requests 2 to 8 come first, in their own order; pull request 5 of this plan follows, since it runs that pruner on the Gradle reference exercise; pull request 6 is stacked on it; the prune plan's pull request 14 (its Task 14.1, the Maven prune) follows pull request 6; pull request 7 of this plan comes after its own pull request 4 and the prune plan's pull request 14. That is a chain with no cycle: prune plan 2 to 8, then this plan 5, then this plan 6, then prune plan 14, then this plan 7, with this plan's 1 to 4 independent until 7. Nothing else in either plan waits for the other.

## A.12 Risks

- **Schema drift.** Ares may add a field, a domain or a version 2. Mitigated by refusing unknown keys and any version but 1, and by pinning the Ares commit in `ares_policy.sh`'s header; a change in Ares then shows up as a refusal, not a silent misreading. A weekly job that runs Ares's example policies through the importer is possible later; not in scope.
- **Ares's own Phobos writer** keeps emitting a format Phobos refuses. Harmless while Ares does not dispatch it, confusing to a reader; outside this repository (decision Q1).
- **Ares timeout semantics.** A policy written for Ares with `timeout: 3000` bounds the whole Gradle build at 3 s under Phobos, which no build survives. The example policies in the Ares repository do exactly that. Imported anyway by decision Q4; the summary line names the timeout.
- **UDP below Landlock version 10.** By decision Q6 every imported network entry brings a `udp` rule, which the enforcer refuses below version 10 unless a `udp` loopback wildcard sits beside it. Decision R1 puts that wildcard into every programming language configuration, so such a run starts on today's runner kernels. The cost is stated in A.5.3: UDP to every loopback port is permitted for every Ares run, and the imported `udp` rules rest on the connect guard alone on every kernel. If the wildcard were ever removed from a configuration file, its Ares runs with a granted entry that names a port would fail closed with status 125 again below version 10, never run unenforced.
- **No Maven base yet.** Until pull request 7, a `MAVEN` policy is refused for want of its configuration file, which is clear and early, but means Maven exercises cannot use the import. Pull request 7 waits for the prune plan's pull request 14, whose Task 14.1 runs the Maven prune (A.11, ordering).
- **JDK 25 for every run (decision R4).** Pull request 5 moves the run-phase image to Artemis's `java25-1`, so every graded build, Gradle builds included, runs on JDK 25, Maven 3.9.16 and Gradle 9.8.0 instead of JDK 17, Maven 3.9.11 and Gradle 9.0.0. The JDK keeps its path, so no base path has to follow it, but the shipped Java base does not carry a JDK 25 Gradle build (A.4.4, measured), which is why the same pull request re-prunes it. A Gradle exercise whose wrapper names a Gradle before 9.1.0 cannot run on JDK 25 at all, and one without the four settings of A.4.4 forks a single-use daemon whose `setsid` the group lock refuses: both fail visibly, and the `Breaking changes and migration` section of pull request 5 tells instructors what to change.
- **An internal Gradle property.** `org.gradle.internal.instrumentation.agent=false` (A.4.4) is internal to Gradle. If a later Gradle renames it, the fork returns, the prune reports a fixed-rule refusal of `setsid` before any grant, and the Gradle bump is held back until it is re-measured.
- **Template drift.** Artemis will raise the versions in its template. The reference exercise, its manifest and the base image digest are then changed together in one pull request, the prune is run again, and the adopted base is replaced in another; until then grading keeps the pinned set, which matches the base. A graded exercise whose `pom.xml` names other versions than the reference reads jars the base does not name and is refused with `EACCES`, visibly, never silently widened.
- **A Maven base only as wide as its reference.** The pruned base covers what the reference exercise of A.4.3 loads: Maven, the template's plugins, Ares 2 with its dependencies, the AspectJ weaver and the Ares agent, per file under `/root/.m2/repository` (prune plan A.6.5 treats `/root` as a fine-grained root). An instructor's `pom.xml` that adds a dependency the template does not have needs that jar granted by the exercise's own configuration, or the run fails with `EACCES` rather than reaching anything ungranted.
- **A language slipping into code.** Mitigated by the constraint, the review rule and `no_language_in_code.sh`.
- **Bash YAML reader correctness.** Mitigated by the subset's refuse-by-default design and a test table for every construct both ways.
- **Performance.** Policies are tens of lines; bash is adequate.
- **The covered-entry skip misunderstood as a hole.** Mitigated by the summary line and documentation; it is neutral for Landlock by construction and tested with the symbolic link and missing-ancestor cases.

## A.13 Decisions, and the questions that remain

Markus decided on 2026-10-05:

| | Decision |
| --- | --- |
| Q1 | Phobos translates the Ares file itself. |
| Q2 | Relative paths and `${PROJECT_ROOT}` resolve against the tail flags' last `--chdir`; a new flag `--project-root` is added and wins where given; with neither, they are refused. |
| Q3 | `${java.home}`, `${user.home}` and `${java.io.tmpdir}` are supported, and Phobos determines them itself, through the programming language configuration (A.4.2), so the code stays independent of any language. |
| Q4 | The Ares timeout is imported, although it then bounds the whole build. |
| Q5 | A network entry is imported only when all three flags are `true`; a partial combination is refused. |
| Q6 | A granted network entry becomes a TCP and a UDP rule. |
| Q7 | One base per build tool, selected by the programming language configuration. |
| Q8 | A Java configuration runs under the Java base only, never under `BasePhobos.cfg`. |
| Q9 | `createAllFiles` with `deleteAllFiles` adds `[restructure]`. |
| Q10 | A missing imported path is refused in every section. |
| Q11 | Java name patterns are not checked: Phobos is independent of every programming language. |
| Q12 | The covered-entry skip, with its summary line. |
| Q13 | A DNS name with a trailing dot is refused. |
| Q14 | Detection by the `.yaml` and `.yml` extension. |
| Q15 | Non-ASCII paths are allowed, with a strict UTF-8 check. |
| R1 | Every programming language configuration adds `allow localhost udp`, a `udp` loopback rule with no port, to its base, in its own `[connect]` section (A.4.2), never in Phobos core and never in `BaseLanguage-java.cfg`. An Ares policy with a granted network entry that names a port therefore runs below Landlock version 10, its `udp` rules held by the connect guard alone (A.5.3, A.8). Shipped in pull request 4. |
| R2 | The Maven reference exercise is built in this repository by us (A.4.3, pull request 6), pinned and offline, in the shape the prune plan of pull request 162 consumes; its base is produced by that plan's pruner (its Task 14.1) and adopted in pull request 7. |
| R3 | The reference exercise runs Ares 2 as an Artemis Maven exercise does, taken from Artemis's Java Maven test template: Ares 2 with its dependencies, AspectJ weaving and the Ares agent (A.4.3). Every artefact is pinned and pre-loaded, in the run-phase image and therefore in the prune image built from it, so the prune stays offline and grading reads the bytes the prune observed (pull requests 5 and 6). Everything language specific stays in the exercise, the image and the Java programming language configuration; nothing enters Phobos core. |
| R5 | A fourth generic primitive, `password-database home`, reads the home directory from the password database entry of the process's real uid, and the Java configurations determine `user.home` with it, since the JVM takes `user.home` from there and not from `HOME` (measured: `HOME=/var/tmp` still gives `/root`). It names no language. Shipped with pull request 2. |
| R6 | A placeholder is determined only when a configuration or policy uses it, and then once. A run whose policy never writes `${user.home}` starts as uid 65534 (home `/nonexistent`) under a Java configuration; one that writes it is refused exactly as before, with the same message, configuration file and line. Shipped with pull request 2. |
| R4 | The run-phase image moves to `ls1tum/artemis-maven-template:java25-1`, pinned by digest, so every graded run, Gradle exercises included, runs on JDK 25 (pull request 5). No base path names a JDK 17 location, but the shipped Java base does not carry a JDK 25 Gradle build, so pull request 5 also adds a Gradle reference exercise on Gradle 9.8.0, the first Gradle line that runs on Java 25 being 9.1.0, and re-prunes `BaseLanguage-java.cfg` from it with the prune plan's pruner, listing every widening and narrowing and keeping the base entries an ancestor covers (A.4.4). |

And the standing rule: nothing may endanger Phobos's independence of programming languages; whatever depends on a language is done only on the basis of the programming language configuration.

No question remains open.

---

# Part B: Implementation tasks

The tasks below are grouped by pull request. Every suite runs on Linux; on this Mac use the local `phobos-test-runner` image as the memory notes describe, with the repository mounted read-only and no extra privileges:

```bash
docker run --rm -v "$PWD":/w:ro -w /w phobos-test-runner bash tests/unit/phobos-tools-policysystem/yaml_subset.sh
```

## Pull request 1: the YAML subset reader

### Task 1: Records for the accepted subset

**Files:**
- Create: `core/phobos-tools-policysystem/phobos-policy-yaml.sh`
- Modify: `core/phobos-tools-common/phobos-common.sh` (one `source` line after `phobos-policy-parse.sh`, with its `# shellcheck source=` line)
- Test: `tests/unit/phobos-tools-policysystem/yaml_subset.sh`
- Modify: `.github/workflows/test.yml` (a step running the new suite, next to `address_literals.sh`)

**Interfaces:**
- Consumes: `refuse_cfg`, `PARSE_LOCATION`, `refuse_binary_cfg`, `new_scratch_file` from `phobos-common.sh`.
- Produces: `read_yaml_subset <file> <records_out>`, writing `<line>\t<path>\t<type>\t<value>` lines in document order; refuses through `refuse_cfg`, so it must be called plainly, never in a subshell.

- [ ] **Step 1: Write the failing test**

```bash
#!/usr/bin/env bash
# Which YAML a policy may be written in, and the flat records the reader makes of it. The reader
# accepts a strict subset and refuses everything else, so a construct two YAML readers could read
# differently is refused instead of read one way; this suite pins both directions.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../core"
# shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Writes its standard input to a fixture and prints the records the reader makes of it, or
# "<status>|<message>" when the reader refuses it.
records_of() {
  local fixture="${WORK}/policy.yaml"
  local out="${WORK}/records"
  local message
  cat > "$fixture"
  message="$( (read_yaml_subset "$fixture" "$out") 2>&1 > /dev/null)"
  local status=$?
  if (( status == 0 )); then cat "$out"; else printf '%s|%s' "$status" "$message"; fi
}

echo "== accepted =="
expected=$'1\t.\tmap\t\n1\t.a\tint\t1\n2\t.b\tstr\tx y\n3\t.c\tbool\ttrue\n4\t.d\tnull\t'
actual="$(printf 'a: 1\nb: "x y"\nc: true\nd:\n' | records_of)"
check "scalars of every type" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.l\tseq\t\n2\t.l[0]\tmap\t\n2\t.l[0].k\tstr\tv\n3\t.l[0].n\tint\t0\n4\t.e\tseq\t'
actual="$(printf 'l:\n  - k: v\n    n: 0\ne: [ ]\n' | records_of)"
check "a sequence of mappings and an empty flow sequence" "$expected" "$actual"

actual="$(printf 'l:\n- k: v\n  n: 0\ne: []\n' | records_of)"
check "a sequence at its key's own column reads the same" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.s\tstr\tit'"'"$'s\n2\t.t\tstr\ta\\b"c'
actual="$(printf "s: 'it''s'\nt: \"a\\\\\\\\b\\\\\"c\"\n" | records_of)"
check "both quote styles and their escapes" "$expected" "$actual"

echo "== refused =="
for case in \
  'a: &x 1|anchor' 'a: *x|alias' 'a: !!str 1|tag' 'a: |\n  x|block scalar' 'a: ["-l"]|flow' \
  'a: 1\na: 2|appears twice' 'a: yes|true or false' 'a: True|true or false' 'a: 010|ambiguous' \
  'a: 0x10|ambiguous' 'a: 1.5|ambiguous' 'a: 1_000|ambiguous' 'a: 1:20|ambiguous' 'a: "x\\n"|escape' \
  'a: 1\n---\nb: 2|one document' 'a: 1\n...|one document' 'a: x\n  y|continuation' 'l:\n  -\n|alone' \
  '"a": 1|key' 'a: 1\r|carriage return' 'a: >\n  x|block scalar' 'a: {b: 1}|flow' 'a: -l|indicator' \
  'a: ::1|indicator' 'a: "\xc3\x28"|UTF-8' 'a: "x\xc2\x85y"|control' 'a: "x\xe2\x80\xaey"|bidirectional' 'a: 8e1|ambiguous' 'a: +80|ambiguous' \
  'a: 0o120|ambiguous' 'a: 80.0|ambiguous' 'a: on|true or false' 'a: n|true or false'; do
  text="${case%|*}"
  needle="${case##*|}"
  result="$(printf '%b\n' "$text" | records_of)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${needle}"* && "${result#*|}" == *"line "* ]]; then
    ok "refused, saying '${needle}' and a line: ${text}"
  else
    bad "refused, saying '${needle}' and a line: ${text}" "status ${PHB_EPOLICY}" "${result}"
  fi
done
for bytes in 'a:\t1\n' '\xef\xbb\xbfa: 1\n' 'a: 1\x00\n'; do
  result="$(printf '%b' "$bytes" | records_of)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" ]]; then ok "refused: ${bytes}"; else bad "refused: ${bytes}" "status ${PHB_EPOLICY}" "${result}"; fi
done

expected=$'2\t.\tmap\t\n2\t.a\tint\t1'
actual="$(printf -- '---\na: 1 # comment with \xc3\xa4\n# a full-line comment\n' | records_of)"
check "a leading document marker and comments, any valid UTF-8 in a comment" "$expected" "$actual"

expected=$'1\t.\tmap\t\n1\t.p\tstr\t/srv/\xc3\xbcbung'
actual="$(printf 'p: "/srv/\xc3\xbcbung"\n' | records_of)"
check "a value with a non-ASCII name in valid UTF-8" "$expected" "$actual"

finish
```

- [ ] **Step 2: Run it to see it fail**

Run: `docker run --rm -v "$PWD":/w:ro -w /w phobos-test-runner bash tests/unit/phobos-tools-policysystem/yaml_subset.sh`
Expected: FAIL, `read_yaml_subset: command not found` in every case.

- [ ] **Step 3: Implement the reader**

The reader is three functions plus helpers, each with its own comment block above it (AGENTS.md):

```bash
# Sets yaml_value_type to the type of one plain scalar, "bool", "null", "int" or "str", and
# refuses one that YAML readers resolve differently (a boolean-like word other than true and
# false, or a spelling a YAML 1.1 reader takes for a number). Takes the scalar. Assumes it runs
# inside read_yaml_subset, with PARSE_LOCATION naming the line, and that it is called plainly, so
# that a refusal ends the run.
yaml_plain_type() {
  local text="$1"
  local yaml_lower=""
  case "$text" in
    true|false) yaml_value_type="bool"; return 0 ;;
    ""|"~"|null|Null|NULL) yaml_value_type="null"; return 0 ;;
  esac
  yaml_ascii_lower "$text"
  if [[ "$yaml_lower" =~ $YAML_BOOLEAN_LIKE_PATTERN ]]; then
    refuse_cfg "${text@Q} is read as a boolean by some YAML readers and as a string by others; write true or false, or quote it"
  fi
  if [[ "$text" =~ $YAML_PLAIN_INT_PATTERN ]]; then
    yaml_value_type="int"
    return 0
  fi
  if [[ "$text" =~ $YAML_NUMBER_LIKE_PATTERN || "$yaml_lower" =~ $YAML_SPECIAL_FLOAT_PATTERN ]]; then
    refuse_cfg "${text@Q} is ambiguous: YAML readers disagree on whether it is a number. Write a plain whole number without sign or leading zero, or quote it"
  fi
  yaml_value_type="str"
}
```

The type is set in a variable of `read_yaml_subset`, not printed: a helper called in a command substitution runs in a subshell, where `refuse_cfg` would end only the subshell. Every helper of the reader therefore hands its result back through a local of `read_yaml_subset`, by dynamic scope. The patterns are constants written with listed characters (`[0123456789]`, the ASCII letters), not `[[:digit:]]` or `[A-Z]`, which a UTF-8 locale can widen.

`read_yaml_subset` reads the file line by line with `while IFS= read -r line || [[ -n "$line" ]]`, after `refuse_binary_cfg "$file"`; it keeps a stack of `(indent, path, kind, next_index)` frames in parallel arrays (`frame_indent`, `frame_path`, `frame_kind`, `frame_next`, one array per line of declaration), strips comments with a quote-aware scan (`yaml_strip_comment`), splits `key: value` and `- ...` (`yaml_split_line`), unquotes scalars (`yaml_unquote`, which refuses an escape other than `\\` and `\"` and an unterminated quote), pops frames whose indent is not smaller than the current line's, refuses an indent that matches no open frame, records a duplicate key by keeping one associative array per mapping path (`seen_key["<path>/<key>"]=<line>`), and appends one record per node. Every refusal sets `PARSE_LOCATION="${file@Q}, line ${number}"` first, and the function clears `PARSE_LOCATION` before it returns, as `parse_cfg_policy` does.

- [ ] **Step 4: Run the suite and the linters**

Run: the docker command above, then `shellcheck -x -S warning core/phobos-tools-policysystem/phobos-policy-yaml.sh tests/unit/phobos-tools-policysystem/yaml_subset.sh` and the function-comment `awk` check from CLAUDE.md.
Expected: every check passes, 0 failed, 0 skipped.

- [ ] **Step 5: Commit**

```bash
git add core/phobos-tools-policysystem/phobos-policy-yaml.sh core/phobos-tools-common/phobos-common.sh tests/unit/phobos-tools-policysystem/yaml_subset.sh .github/workflows/test.yml
git commit -m "Read a strict subset of YAML into flat records with line numbers"
```

## Pull request 2: the programming language configurations

### Task 1a: The language-independent loader and the Gradle configurations

**Files:**
- Create: `core/phobos-tools-policysystem/phobos-language-configuration.sh`
- Create: `core/config/language-configurations/JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ.cfg`, `JAVA_USING_GRADLE_ARCHUNIT_AND_INSTRUMENTATION.cfg`, `JAVA_USING_GRADLE_WALA_AND_ASPECTJ.cfg`, `JAVA_USING_GRADLE_WALA_AND_INSTRUMENTATION.cfg`, each as in A.4.2
- Modify: `core/phobos-tools-common/phobos-common.sh` (source the loader), `docker/run_phase/java/Dockerfile` and `.github/scripts/assemble-run-phase-context.sh` (ship `config/language-configurations/` to `${PHOBOS_HOME}/language-configurations/`)
- Test: `tests/unit/phobos-tools-policysystem/language_configuration.sh`, `tests/unit/phobos-tools-policysystem/no_language_in_code.sh`
- Modify: `.github/workflows/test.yml`, `tests/README.md`

**Interfaces:**
- Consumes: `refuse_cfg`, `PARSE_LOCATION`, `refuse_binary_cfg`.
- Produces: `load_language_configuration <name> <home>`, which sets `LANGUAGE_CONFIGURATION_BASES` (an array of absolute base file paths) and records how and on which line each placeholder is determined, or refuses; `determine_language_placeholder <name>`, which determines a placeholder on its first use, keeps it in `LANGUAGE_CONFIGURATION_PLACEHOLDERS` and sets `LANGUAGE_PLACEHOLDER_VALUE`, or refuses; `language_configuration_exists <name> <home>`.

- [ ] **Step 1: Write the failing tests.** In `language_configuration.sh`, a temporary home with a `language-configurations/` folder and a fake command on a `PATH` of its own (`${WORK}/bin/tool -> ${WORK}/opt/tool/bin/tool`, a symbolic link chain), then: `environment HOME` gives `$HOME`; `environment UNSET_VARIABLE /tmp` gives `/tmp`; `command-ancestor tool 2` gives `${WORK}/opt/tool`; `fixed /srv` gives `/srv`; a `[base]` entry `BaseLanguage-x.cfg` resolves beside the home and `bases/BaseLanguage-y.cfg` under `language-configurations/`. Refused, each with file and line: an unknown section, an unknown primitive, `command-ancestor missing 2`, a value that is not an existing directory, a relative `fixed`, a `[base]` entry with `..`, a base that does not exist, CR, BOM, NUL. In `no_language_in_code.sh`, one check that `grep -rn -E 'JAVA_USING|java\.home|user\.home|java\.io\.tmpdir' core --exclude-dir=config` finds nothing.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement** the loader as small documented functions, one per primitive (`determine_by_environment`, `determine_by_command_ancestor`, `determine_fixed`, `determine_by_password_database`), each refusing through `refuse_cfg`; no language name anywhere.
- [ ] **Step 4: Run the suites and the linters**, and build the run-phase image to check the folder lands in `${PHOBOS_HOME}/language-configurations/`.
- [ ] **Step 5: Commit** `Read programming language configurations, the one place a language enters Phobos`.

## Pull request 3: the Ares importer for the file system and the timeout

### Task 2: The schema check

**Files:**
- Create: `core/phobos-tools-policysystem/phobos-policy-ares.sh`
- Modify: `core/phobos-tools-common/phobos-common.sh` (source it after the YAML reader)
- Test: `tests/unit/phobos-tools-policysystem/ares_policy.sh`
- Modify: `.github/workflows/test.yml` (a step for the suite)

**Interfaces:**
- Consumes: `read_yaml_subset` (Task 1), `language_configuration_exists` (Task 1a), `refuse_cfg`.
- Produces: `ares_check_schema <records> <home>`, which refuses any record set that is not a valid version 1 policy per A.5.1 and the structural rows of A.5.2 to A.5.5, including a configuration name with no file under `<home>/language-configurations/`; `ares_record_value <records> <path>` and `ares_record_line <records> <path>`, which print the value and the line of the record at a path, and print nothing when there is none.

- [ ] **Step 1: Write the failing test** with a fixture writer `policy_with()` that prints the documented example policy (A.1) with one line replaced, and a table of the form used in Task 1: the example passes; each of these fails with its message and line: version `2`, version `"1"`, a missing `regardingTimeouts`, an extra root key, `readAllFiles` missing, `readAllFiles: "true"`, `onThePort: "80"`, `theFollowingTestBehaviorIsConfigured: null`, `theFollowingTestBehaviorIsConfigured: {x: 1}`, a configuration `PYTHON_USING_PIP` with no file, a configuration in lower case, a test class `""`, a command entry with an extra key, `createTheFollowingNumberOfThreads: "10"`, a `${user.home}` in the package, in a test class and in `onTheHost`; and a `${java.home}` in `executeTheCommand` is accepted (commands grant nothing).

```bash
for case in \
  'thisPolicyFileCompliesToThePolicyVersion: 1|thisPolicyFileCompliesToThePolicyVersion: 2|exactly 1' \
  '    regardingTimeouts:|    regardingTimeoutz:|unknown key' \
  '        readAllFiles: true|        readAllFiles: "true"|must be true or false' \
  '        onThePort: 80|        onThePort: "80"|whole number' \
  '  theFollowingProgrammingLanguageConfigurationIsUsed: JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ|  theFollowingProgrammingLanguageConfigurationIsUsed: PYTHON_USING_PIP|has no file' \
  '  theFollowingProgrammingLanguageConfigurationIsUsed: JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ|  theFollowingProgrammingLanguageConfigurationIsUsed: JAVA_USING_MAVEN_WALA_AND_ASPECTJ|has no file'; do
  from="${case%%|*}"
  rest="${case#*|}"
  to="${rest%%|*}"
  needle="${rest#*|}"
  result="$(policy_with "$from" "$to" | parse_result)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${needle}"* ]]; then ok "refused: ${to}"; else bad "refused: ${to}" "status ${PHB_EPOLICY}, '${needle}'" "${result}"; fi
done
```

- [ ] **Step 2: Run it to see it fail** (`ares_check_schema: command not found`).
- [ ] **Step 3: Implement** `ares_check_schema` as a set of small functions, each named after the node it checks (`ares_check_root`, `ares_check_supervised_code`, `ares_check_resource_accesses`, `ares_check_file_entry`, `ares_check_network_entry`, `ares_check_command_entry`, `ares_check_thread_entry`, `ares_check_package_entry`, `ares_check_timeout_entry`), driven by allowed-key and required-key lists held in one constant per node:

```bash
ARES_ROOT_KEYS="thisPolicyFileCompliesToThePolicyVersion regardingTheSupervisedCode"
ARES_FILE_KEYS="onThisPathAndAllPathsBelow readAllFiles overwriteAllFiles createAllFiles executeAllFiles deleteAllFiles"
ARES_NETWORK_KEYS="onTheHost onThePort openConnections sendData receiveData"
ARES_CONFIGURATION_PATTERN='^[ABCDEFGHIJKLMNOPQRSTUVWXYZ][ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*$'
```

(and one constant each for the supervised code, the resource accesses, command, thread, package and timeout keys). Each refusal sets `PARSE_LOCATION` from `ares_record_line`.
- [ ] **Step 4: Run the suite and the linters**; expected all pass.
- [ ] **Step 5: Commit** `Check an Ares 2 policy against its version 1 schema`.

### Task 3: File system mapping, path resolution and the notices

**Files:**
- Modify: `core/phobos-tools-policysystem/phobos-policy-ares.sh`
- Test: `tests/unit/phobos-tools-policysystem/ares_policy.sh`

**Interfaces:**
- Consumes: `ares_check_schema`, `refuse_relative_path`, `refuse_wildcard_path`, `refuse_missing_path`, `new_parse_directory`, `reset_parsed_limits`, `set_parsed_timeout`.
- Produces: `parse_ares_policy <file> <project_root> <base_dir>`, which sets `PARSED_FS_DIR`, `PARSED_NET_FILE`, `PARSED_BIND_FILE`, `PARSED_ACCEPT_FILE`, the `PARSED_*` limits, `PARSED_ARES_CONFIGURATION` and `PARSED_ARES_SKIPPED`, and expands each placeholder a path uses through `determine_language_placeholder`, so only the placeholders the policy uses are determined; `ares_row_covered_by_base <section> <path> <base_dir>`, which succeeds when the covered-entry skip of A.6 applies; `tail_flags_working_directory <tail_flags_file>`, which prints the last `--chdir` value of the tail flags or nothing; `ares_millis_to_timeout <digits>`, which prints the exact seconds with three decimals.

- [ ] **Step 1: Write the failing tests**: for each row of A.5.2 a fixture with one entry under a temporary tree `${WORK}/proj` (created with `mkdir -p` and `: >`), and the expected content of each `.paths` file; `allowed.txt` relative, with the project root `${WORK}/proj`, becomes `${WORK}/proj/allowed.txt`; `${PROJECT_ROOT}/x` likewise; `${java.home}/lib` with a test configuration whose `[placeholders]` names `java.home` becomes that directory's `lib`; `createAllFiles` with `deleteAllFiles` writes `create`, `symlink`, `delete` and `refer` rows; `tail_flags_working_directory` prints the last of two `--chdir` values, ignores one inside a comment, and prints nothing for a tail with none or a missing file; refusals for `*`, `a\\b`, `${HOME}/x` (not named by the configuration), `${java.home}` under a configuration that does not name it, `../x`, `x/../y`, a relative path and `${PROJECT_ROOT}/x` with an empty project root (while an absolute path is still accepted then), a relative project root, a missing path under `overwriteAllFiles` only. Which source gives the project root is decided by the policy program and tested in Task 4. And the conversion table:

```bash
for case in "1|0.001" "999|0.999" "1000|1.000" "1500|1.500" "120000|120.000" "000120000|120.000" "999999999999999999|999999999999999.999"; do
  in="${case%%|*}"
  want="${case##*|}"
  check "ares_millis_to_timeout ${in}" "$want" "$(ares_millis_to_timeout "$in")"
done
```

and the timeout cases: two entries `3000` and `1000` give `PARSED_TIMEOUT=1.000`; an empty list gives `PARSED_TIMEOUT=` and a notice on standard error; `9223372036854775807` is refused by `set_parsed_timeout`'s digit limit.

- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement.** The conversion moves the decimal point on the digit string and never uses arithmetic:

```bash
# Prints a whole number of milliseconds as seconds with exactly three decimals, by moving the
# decimal point, so that no value is rounded and none can overflow the arithmetic. A rounding of
# a value below one second to zero would switch the timeout off, which is why nothing here rounds.
# Takes the digits as the schema check accepted them. Needs no environment.
ares_millis_to_timeout() {
  local digits="${1#"${1%%[!0]*}"}"
  local seconds
  local millis
  while (( ${#digits} < 4 )); do
    digits="0${digits}"
  done
  seconds="${digits:0:${#digits}-3}"
  millis="${digits: -3}"
  seconds="${seconds#"${seconds%%[!0]*}"}"
  printf '%s.%s' "${seconds:-0}" "$millis"
}
```

The tightest-wins comparison:

```bash
# Whether the first whole number is smaller than the second, compared as digit strings so that
# no length overflows the arithmetic. Takes two strings of digits without leading zeros.
# Needs no environment.
digits_less_than() {
  local left="$1"
  local right="$2"
  (( ${#left} != ${#right} )) && { (( ${#left} < ${#right} )); return; }
  [[ "$left" < "$right" ]]
}
```

The tail flags' working directory, the second source of the project root (A.5.2 step 6):

```bash
# Prints the directory the enforcer changes into before it runs the command: the value of the
# last --chdir in the tail flags, which is the one phobos-landlock-filesystem-and-networksystem keeps. Prints nothing when
# the tail flags name none or the file is absent, and never substitutes a current directory for
# it. Reads the tail flags as write_spec does, a "#" starting a comment and the rest split on
# white space. Needs no environment.
tail_flags_working_directory() {
  local file="$1"
  local -a words=()
  local index
  local found=""
  [[ -n "$file" && -f "$file" ]] || return 0
  read -ra words <<< "$(sed -E 's/#.*$//' "$file" | tr '\n' ' ')"
  for (( index = 0; index + 1 < ${#words[@]}; index++ )); do
    [[ "${words[index]}" == "--chdir" ]] && found="${words[index + 1]}"
  done
  printf '%s' "$found"
}
```

The covered-entry skip, which never edits a merged file and answers no whenever it is in doubt:

```bash
# Whether the folded base already grants this section's right on the imported path: the base's
# file for the same section names a path that exists and that, both resolved through their
# symbolic links as the filesystem layer resolves them, is the imported path or an ancestor of it.
# realpath -e is used rather than resolve_symlinks, which passes a path it cannot resolve through
# as written: here a failed resolution has to mean "not covered", never a lexical comparison. For
# an existing path both give the same answer. The root resolves to "/", and "${x%/}/" of it is "/",
# so the root is an ancestor of every path.
# Takes the section file name without ".paths", the absolute imported path, which exists, and the
# base directory phobos-policysystem.sh folded the Base*.cfg into. A missing base path is no
# ancestor, because the filesystem layer drops a missing read or execute path. Assumes GNU realpath,
# which refuse_missing_realpath has established.
ares_row_covered_by_base() {
  local section="$1"
  local path="$2"
  local base_dir="$3"
  local resolved_path
  local candidate
  local resolved_candidate
  [[ -s "${base_dir}/${section}.paths" ]] || return 1
  resolved_path="$(realpath -e -- "$path" 2>/dev/null)" || return 1
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    resolved_candidate="$(realpath -e -- "$candidate" 2>/dev/null)" || continue
    [[ "$resolved_path" == "$resolved_candidate" ]] && return 0
    [[ "$resolved_path" == "${resolved_candidate%/}/"* ]] && return 0
  done < "${base_dir}/${section}.paths"
  return 1
}
```

`ares_resolve_policy_path <value> <project_root>` applies steps 2 to 6 of A.5.2 and prints the absolute path, refusing a relative path or `${PROJECT_ROOT}` when `<project_root>` is empty or relative; `ares_map_file_entry <records> <index> <project_root> <base_dir>` writes the sections of A.5.2, asking `ares_row_covered_by_base` before each row and counting the rows it leaves out in `PARSED_ARES_SKIPPED`; `ares_report_summary` prints the A.7 line. `parse_ares_policy` calls `read_yaml_subset`, `ares_check_schema`, the mappings in order, and, for this pull request, refuses a non-empty `regardingNetworkConnections` with "network permissions in an Ares 2 policy are not imported yet; this Phobos refuses the file rather than run without them".
- [ ] **Step 4: Run the suite and the linters**; all pass.
- [ ] **Step 5: Commit** `Translate the file system and timeout domains of an Ares 2 policy`.

### Task 4: Dispatch, base selection and the project root in the policy program

**Files:**
- Modify: `core/phobos-policysystem.sh` (`fold_cfg_into`, base selection before the base loop, `--project-root`, `--help`)
- Modify: `core/phobos.sh` (`--project-root`, passed to `phobos-policysystem.sh`, and `--help`)
- Test: `tests/integration/ares_policy_program.sh` (new), `tests/integration/malformed_cfg.sh` (extended)
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: `parse_ares_policy`, `ares_row_covered_by_base` and `tail_flags_working_directory` (Task 3), `load_language_configuration` (Task 1a), `fs_union_dir`, `net_union`, `merge_limits`.
- Produces: `select_bases_for_ares_policies <home> <cfg>...`, which reads the configuration name of every `.yaml`/`.yml` file, loads its configuration and sets the base list per A.6, or leaves the existing `Base*.cfg` list when there is no Ares file; the `--project-root <dir>` option of `phobos-policysystem.sh` and `phobos.sh`.

- [ ] **Step 1: Write the failing integration test** in the style of `policy_program.sh`: a temporary `core` copy with `BaseLanguage-java.cfg` beside `phobos-policysystem.sh` and a `language-configurations/` folder whose test configuration names it in `[base]` and names `java.home` in `[placeholders]` as `fixed` on a directory under `${WORK}`, a project tree under `${WORK}/proj` named in the base as `[read]`/`[execute]` and as the tail's `--chdir`, then:
  - an Ares file reading `allowed.txt` is accepted, `read.paths` does not contain `${WORK}/proj/allowed.txt` (skipped as covered), and standard error holds "already covered by the base";
  - an Ares file reading `${WORK}/outside/data.txt` (not under the base) is accepted and `read.paths` contains it;
  - the core holds a second base `BaseOther.cfg`, which a `.cfg`-only run folds and a run with the Ares file does not, since its configuration names only `BaseLanguage-java.cfg`;
  - a configuration whose `[base]` names a missing file is refused, naming it;
  - a symbolic link `${WORK}/proj/link -> ${WORK}/outside` with an Ares entry `link/data.txt` keeps `${WORK}/proj/link/data.txt` in `read.paths` (its resolved target is not under the project tree);
  - a base path that does not exist does not cover an imported path beneath it;
  - a base row `/usr/bin` beside `/usr`, with an Ares entry that also names `/usr/bin` read and execute, leaves the base's `/usr/bin` rows exactly as they were;
  - an exercise `.cfg` with `[read] ${WORK}/proj/allowed.txt` beside the Ares file is still refused by the filesystem layer's hierarchy check when the layer is run over the specification;
  - a `.yaml` and a `.cfg` given together merge, with byte-identical specifications in both orders: union of paths, largest timeout;
  - a run given only an Ares file keeps the network rules of the base, which a run with no `--config` drops (the no-`--config` shape does not apply);
  - the project root follows A.5.2 step 6 and nothing else: a relative Ares path and `${PROJECT_ROOT}` resolve against the tail's last `--chdir` (the same policy with two tail files naming different directories gives two different absolute paths); `--project-root ${WORK}/other` wins over the tail's `--chdir`, also when given through `phobos.sh`; with neither, both are refused, also when the program is started from inside `${WORK}/proj` and the policy file lies there, so neither the caller's current directory nor the policy file's directory is used; a `--project-root` that is relative or does not exist is refused;
  - `${java.home}/lib` resolves to the directory the test configuration determines, and a placeholder it does not name is refused;
  - two Ares files naming different configurations are refused, also when both configurations name the same `[base]`, and a configuration with no file is refused;
  - `createAllFiles` with `deleteAllFiles` writes `[restructure]` as well as `[create]`, `[create-symlink]` and `[delete]`;
  - `x.cfg` holding YAML and `x.yaml` holding a `.cfg` are both refused.
- [ ] **Step 2: Run it to see it fail.**
- [ ] **Step 3: Implement.** In `fold_cfg_into`:

```bash
  case "$cfg" in
    *.yaml|*.yml) parse_ares_policy "$cfg" "$project_root" "$base_dir" ;;
    *)            parse_cfg_policy "$cfg" "$exercise" ;;
  esac
```

`project_root` is computed once, before the loops: the value of `--project-root` where given (refused unless it is an absolute path to an existing directory), otherwise `tail_flags_working_directory "$tail_flags_file"`, otherwise empty, in which case `parse_ares_policy` refuses a relative path or `${PROJECT_ROOT}`. Nothing else is consulted: not `$PWD`, not the policy file's directory. The value and its source go to the debug log. The Ares branch is only reached from the exercise loop, since a base is only ever a `.cfg`. Before the base loop, `select_bases_for_ares_policies` decides the base list (A.6) and loads the configuration, so its placeholders are known when the exercise loop reaches the Ares file. Nothing merged is edited afterwards.
- [ ] **Step 4: Run** `ares_policy_program.sh`, `policy_program.sh`, `filesystem_policy.sh`, `malformed_cfg.sh`, `limit_merge.sh` and the linters; all pass, none skipped.
- [ ] **Step 5: Commit** `Read an Ares 2 policy given to --config and fold it in as an exercise configuration`.

### Task 5: Matrix witnesses and documentation for pull request 3

**Files:**
- Modify: `tests/integration/protection-matrix/policy-syntax.sh`, `filesystem.sh`, `timeout.sh`
- Modify: `README.md`, `core/phobos-tools-policysystem/config_doc.txt`, `SECURITY.md`, `CLAUDE.md`, `tests/README.md`

**Interfaces:**
- Consumes: the matrix `lib.sh` helpers the suites already use for a run, its unprotected control and its layer-off run.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the matrix checks** of A.9 for the file system and the timeout, each with its control and its layer-off run, as the neighbouring checks in the same files are written.
- [ ] **Step 2: Run** the three suites in the run-phase image as `build.yml` does: `docker run --rm --network none --memory 2g --pids-limit 512 -v "$PWD/tests":/tests:ro phobos-run-phase bash /tests/integration/protection-matrix/filesystem.sh` (and likewise for the others); expect the new checks to pass and no new skip.
- [ ] **Step 3: Write the documentation** of A.10 for these domains.
- [ ] **Step 4: Run every linter** of CLAUDE.md's list, `ec` included.
- [ ] **Step 5: Commit** `Hold an imported Ares 2 policy to the protection matrix, and document the import`.

## Pull request 4: the network domain

### Task 6: Network mapping

**Files:**
- Modify: `core/phobos-tools-policysystem/phobos-policy-ares.sh`
- Modify: `core/phobos-tools-policysystem/phobos-language-configuration.sh` (the `[connect]` section, decision R1)
- Modify: `core/phobos-policysystem.sh` (`select_bases_for_ares_policies` folds the configuration's `[connect]` rows into the base, A.6)
- Modify: the four `core/config/language-configurations/JAVA_USING_GRADLE_*.cfg` (a `[connect]` section holding `allow localhost udp`, with a comment above it saying why: decision R1, and that it must not move into `BaseLanguage-java.cfg`)
- Test: `tests/unit/phobos-tools-policysystem/ares_policy.sh`, `tests/unit/phobos-tools-policysystem/language_configuration.sh`, `tests/integration/ares_policy_program.sh`, `tests/integration/protection-matrix/network.sh`, `policy-syntax.sh`
- Modify: `README.md`, `config_doc.txt`

**Interfaces:**
- Consumes: `append_connect_rule`, `is_ipv4_literal`, `is_ipv6_literal`, `net_union`.
- Produces: `ares_network_rule_line <host> <port>`, which prints the `allow ...` line of A.5.3 or refuses; `ares_map_network_entry` hands it to `append_connect_rule` twice, once as it is and once with ` udp` appended; `load_language_configuration` additionally sets `LANGUAGE_CONFIGURATION_CONNECT_FILE`, a rules file in the format `append_connect_rule` writes, empty when the section is absent.

- [ ] **Step 1: Write the failing tests** for every cell of A.5.3:

```bash
for case in "localhost|80|allow localhost:80" "localhost|0|allow localhost" "127.0.0.1|0|allow 127.0.0.1:*" \
  "::1|443|allow [::1]:443" "::1|0|allow [::1]" "::ffff:127.0.0.1|8080|allow [::ffff:127.0.0.1]:8080" \
  "example.org|443|allow example.org:443" "*|443|allow *:443"; do
  # each granted entry writes this line and the same line with " udp"
  host="${case%%|*}"
  rest="${case#*|}"
  port="${rest%%|*}"
  want="${rest#*|}"
  check "ares_network_rule_line ${host} ${port}" "$want" "$(ares_network_rule_line "$host" "$port")"
done
```

and the refusals: `example.org` with 0, `*` with 0, `example.org.` with 443, `70000`, each partial flag combination (six of them). For the `[connect]` section of the configuration, the `language_configuration.sh` and `ares_policy_program.sh` rows of A.9. In the matrix, the `network.sh` row of A.9, both directions: under a shipped `GRADLE` configuration, an imported `localhost` entry on the probe server's port connects over TCP and the next TCP port is refused; a datagram to that port, to another port of `127.0.0.1` and to `127.0.0.2` goes on every kernel, with no status 125 below version 10; a datagram to `192.0.2.1` and to an unnamed port of an imported `10.0.0.1` entry is refused with `EACCES`, while the named port of that entry meets `ENETUNREACH`; a `.cfg`-only `udp` rule that names a port is still refused with 125 below version 10; each with control and layer-off run.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement** `ares_network_rule_line` and `ares_map_network_entry`, which calls `append_connect_rule "$(ares_network_rule_line "$host" "$port")" "$net"` with `PARSE_LOCATION` naming the entry's line, and remove the interim refusal of Task 3. Teach the loader the `[connect]` section (one documented function, `read_configuration_connect_section`, which calls `append_connect_rule` line by line with `PARSE_LOCATION` naming the configuration file and line, and then refuses the row unless its host passes `is_loopback_host` and its port is `*`), fold `LANGUAGE_CONFIGURATION_CONNECT_FILE` into the base's `net.rules` with `net_union` in `select_bases_for_ares_policies`, and add the section to the four `GRADLE` files. No script under `core/` names the rule; it is data only.
- [ ] **Step 4: Run** the unit, integration and matrix suites and the linters; all pass.
- [ ] **Step 5: Commit** `Translate the network domain of an Ares 2 policy into [connect] rules for TCP and UDP, and let a programming language configuration add [connect] rows to its base`.

## Pull request 5: the run-phase image on JDK 25, and the Java base re-pruned for it

Based on `main`, first of the second stack (A.11); opened once the prune plan's pull request 8 has merged.

### Task 6a: Move the run-phase image to `java25-1`, and re-prune the Java base on it

**Files:**
- Modify: `docker/run_phase/java/Dockerfile` (both `FROM` lines, with the comment above the first saying why this image: Artemis's default Java image, and release 25; the `gradle-repository` stage and its copy into the final stage, each with a comment saying why the grading image must hold exactly these bytes)
- Create: `var/tmp/testing-dir/java/gradle-reference/` with the files A.4.4 lists, and `docker/run_phase/java/gradle-repository.sha256`
- Modify: `.github/scripts/assemble-run-phase-context.sh` (the Gradle exercise and its manifest in the build context)
- Modify: `core/config/BaseLanguage-java.cfg` (replaced by the re-pruned base, A.4.4)
- Modify: `tests/integration/filesystem_policy.sh` only if a row it pins changes, and then only as AGENTS.md allows
- Modify: `README.md` and `CLAUDE.md` wherever they name the run-phase base image, its JDK or Gradle

- [ ] **Step 1:** Look up the multi-architecture index digest of `ls1tum/artemis-maven-template:java25-1` with `docker buildx imagetools inspect` and pin it in both `FROM` lines. Fetch Artemis's Gradle test template at the current `develop`; if it differs from what A.4.4 records at `a5bb83b`, follow it and update A.4.4. Pin Gradle 9.8.0 in the exercise's `gradle-wrapper.properties` with `distributionSha256Sum`.
- [ ] **Step 2:** Write the Gradle exercise and the `gradle-repository` stage, and generate the manifest from its first run, as Task 6b Step 3 does for Maven.
- [ ] **Step 3: Measure the fork, both directions,** in the image built from this branch, ordinary container, `--network none`: `./gradlew --offline --info clean test` in the exercise prints no "single-use Daemon" line, and under `phobos.sh` no `setsid` refusal appears; with `org.gradle.internal.instrumentation.agent=false` removed from a throwaway copy, the "single-use" line and the `setsid` refusal return. Put the output in the body.
- [ ] **Step 4: Re-prune.** Run the prune plan's pruner on the key `java` with the prune image built `FROM` this branch's run-phase image, as that plan's Task 14.1 runs it for Maven (its compose service, `--stage all`, the orchestrator with `--no-deps`). Read the record: both tests passed in all three baseline runs, no fixed-rule refusal, every containment check refused, every grant under `/root` a single file.
- [ ] **Step 5: Adopt it.** Replace `core/config/BaseLanguage-java.cfg` with the orchestrator's base. Run `tests/policy-redundancy-probe.sh` over the old base, and add back unchanged every base entry an ancestor covers that the new base lacks (A.4.4); list in the body every row added, widened, dropped or narrowed, each widening as "this now permits X, which it did not permit before".
- [ ] **Step 6:** Build the image on both architectures as the `run-phase` job of `build.yml` does, and run every acceptance suite and the protection matrix in it, in an ordinary container: the counts of `main`, nothing new skipped, `java -version` reporting 25, and `tests/integration/filesystem_policy.sh` passing unchanged, which proves the `/usr/bin` acceptance case in both directions.
- [ ] **Step 7:** Lint (`hadolint`, `shellcheck`, `ec`) and commit the files by name: `Build the run-phase image on Artemis's JDK 25 Maven image, and re-prune the Java base for it`. The body fills `Breaking changes and migration` with the JDK, Maven and Gradle change and the four Gradle settings an exercise needs (A.4.4, A.12).

## Pull request 6: the Maven reference exercise and its pre-loaded repository

Stacked on pull request 5 (A.11).

### Task 6b: The exercise, and the repository the image carries for it

**Files:**
- Create: `var/tmp/testing-dir/java-maven/maven-reference/build_script.sh` (executable), `prune.json`, `pom.xml`, `SecurityPolicy.yaml`, `assignment/src/de/phobos/reference/Adder.java`, `test/de/phobos/reference/AdderTest.java`, exactly as A.4.3 lists them
- Create: `docker/run_phase/java/maven-repository.sha256`
- Modify: `docker/run_phase/java/Dockerfile` (the `maven-repository` stage and the `COPY --from=maven-repository` into the final stage, each with a comment saying why the grading image must hold exactly these bytes)
- Modify: `.github/scripts/assemble-run-phase-context.sh` (the exercise and the manifest in the build context)
- Modify: `CLAUDE.md` (the Tech Stack line on Java), `AGENTS.md` (the sentence calling the checker the only Java here)

- [ ] **Step 1:** Fetch Artemis's Java Maven test template (`pom.xml`, `SecurityPolicy.yaml`) and `templates/localci/java/build_and_run_tests.sh` at the current `develop`; if they differ from what A.4.3 records at `a5bb83b`, follow the current template and update A.4.3's versions in the same pull request. Say in the body which commit was used.
- [ ] **Step 2:** Write the exercise files of A.4.3, one declaration per line in the Java, LF, final newline. `build_script.sh` is bash, `set -euo pipefail`, and does nothing but `exec mvn --offline --batch-mode -DfailIfNoTests=true clean test` in `/var/tmp/testing-dir`.
- [ ] **Step 3:** Write the `maven-repository` stage of A.4.3 and generate the manifest from its first run: the SHA-256 of every file the online `clean test` added under `/root/.m2/repository`, sorted, LF. Expected: the ten jars A.4.3 lists, with whatever checksum and resolver files Maven writes or changes beside them, and nothing outside `/root/.m2/repository`.
- [ ] **Step 4: Measure, both directions**, in the image built from this branch, ordinary container, `--network none`: copy the exercise to `/var/tmp/testing-dir` and run the build script; expect status 0 and both test cases passed in `target/surefire-reports/TEST-de.phobos.reference.AdderTest.xml`, the Ares agent in `target/ares/ares-agent.jar`, and an identical list of paths and SHA-256 for the whole of `/root/.m2` taken immediately before and after the run (record any difference: that is a write grant the prune will find). Run it once more under `phobos.sh` with a permissive exercise configuration and every layer on; expect it to pass. Then, on throwaway copies: without `test/`, status 1 and `No tests to run!`; with `ares` pinned to a version the repository lacks, status 1 and `in offline mode`. Then refuse the image on purpose, three times: change one byte of one manifest hash (the build fails at `sha256sum`), remove one line (the build fails at the path comparison, an added file not listed), and add a line for a file the run does not produce (the build fails at the path comparison, a listed file missing). Put the commands and their output in the body.
- [ ] **Step 5:** Run `ec --no-color` on the new files, `shellcheck -x -S warning` on `build_script.sh` and `assemble-run-phase-context.sh`, and `hadolint` on the Dockerfile.
- [ ] **Step 6: Commit** the files by name: `Add the Maven reference exercise and pre-load what it needs into the run-phase image`.

## Pull request 7: the Maven base

### Task 6c: Adopt the pruned base and ship the Maven configurations

Starts only when pull requests 4 and 6 of this plan and pull request 14 of the prune plan have merged (A.11, ordering).

**Files:**
- Create: `core/config/language-configurations/bases/BaseLanguage-java-maven.cfg` (the orchestrator's `BaseLanguage-java-maven.cfg` from the prune plan's Task 14.1, unedited, with a comment header naming the pruner run, its record, the image digest and the manifest's SHA-256)
- Create: one `core/config/language-configurations/JAVA_USING_MAVEN_*.cfg` per configuration name that passes Step 2, each naming `bases/BaseLanguage-java-maven.cfg` in `[base]`, with the `[placeholders]` and `[connect]` of the `GRADLE` files
- Modify: `tests/integration/ares_policy_program.sh`

- [ ] **Step 1:** Take the base and the record from the prune plan's Task 14.1 run. Read the record's widening list and its containment checks; list every grant in the body as "this now permits X, which it did not permit before" for a `MAVEN`-configured run.
- [ ] **Step 2:** In the run-phase image, with the pruned base and the four candidate configuration files placed in a scratch copy of `${PHOBOS_HOME}` (none is shipped yet), run the reference exercise under `phobos.sh --config SecurityPolicy.yaml` (the exercise's own Ares policy, imported), once for each of the four `MAVEN` configuration names, changing only that name on a throwaway copy. Expected: both tests pass for each name; a name that fails goes back to the prune as one more exercise under the key `java-maven` (A.4.3), and its configuration file is not shipped until it passes.
- [ ] **Step 3:** Commit the base unedited and the configuration files of Step 2. A hand edit of a pruned base is not part of this task; a grant that looks wrong goes back to the prune.
- [ ] **Step 4:** Extend `ares_policy_program.sh`: a `MAVEN` policy folds only the Maven base and the configuration's `[connect]` rows, and a `.cfg`-only run in the same core still folds only the top-level `Base*.cfg`, never the Maven base; the reference exercise's own `SecurityPolicy.yaml` passes under `phobos.sh` in the run-phase image, and a canary file the test creates under `/srv`, which the base does not name, is still refused for read.
- [ ] **Step 5:** Commit `Add the Maven base and the Maven programming language configurations`.

## Pull request 8 (only if #122 has merged): the documentation site

### Task 7: Docusaurus page

**Files:**
- Create: `documentation/docs/user/policy-reference/ares-2-policy.md`, `documentation/docs/user/policy-cookbook/importing-an-ares-2-policy.md`

- [ ] **Step 1:** Write the page from A.5 and A.8, in the shape of the neighbouring section pages.
- [ ] **Step 2:** Build the site as #122's workflow does (`pnpm install --frozen-lockfile` and `pnpm build` in `documentation/`) and check the page renders and its links resolve.
- [ ] **Step 3:** Commit `Document the Ares 2 policy import on the documentation site`.

---

## Review record

The first version was reviewed in a four-round review dialogue; that review replaced a post-merge edit of the merged rows with the import-time covered-entry skip against the base, made the skip resolve with `realpath -e`, added the case-by-case YAML contract table, stated the working-directory integration requirement, and narrowed the schema-fidelity claim. After the owner's decisions of 2026-10-05 the plan was revised (programming language configuration files, base selection by configuration, `--project-root`, placeholders, `[restructure]`, UDP, strict UTF-8 in place of the earlier ASCII-only rule) and reviewed again in five rounds, which aligned the project-root rule of A.5.2 step 6 with Part B and the tests of Part B with A.9; the reviewer approved the revision explicitly after the fifth round.

The decisions on R1 and R2 were recorded together with the matching changes to the prune plan of pull request 162 and reviewed over both plans at once in three rounds. The review narrowed the `[connect]` section of a programming language configuration to loopback rules without a port, so that a configuration cannot become a second place for egress rules, removed the build command the prune plan had repeated from A.4.3, and kept the prune plan's orchestrator run from pruning the exercise a second time. Several first-round points were withdrawn once checked against the text (the status 125 contract, what `localhost` covers, when `--connect-udp` is emitted, the feasibility of the matrix cases, and the ordering between the plans, which the reviewer confirmed has no cycle). The reviewer then approved explicitly: "I approve, no remaining concerns."

The decision on R3 was recorded after the template, the Artemis images and Ares 2.1.5 had been read and measured, and was reviewed over both plans in three further rounds. The review made the image's manifest check compare the set of new or changed repository files with the manifest's paths, not only their hashes, replaced a modification-time check of `/root/.m2` with a comparison of paths and hashes before and after the run, gated pull request 5 on the answer to R4, and, in the prune plan, added the manifest mount, qualified what compaction leaves ungranted under `/root/.m2`, and ordered the image check after the service it uses. The reviewer approved explicitly: "I approve, no remaining concerns."

Markus then decided R4. Before it was recorded, the shipped Java base was checked path by path against the JDK 25 image, Gradle's compatibility matrix was read, and a Gradle 9.8.0 build was run under `phobos.sh` with the shipped base on JDK 25, which showed the base does not carry it and measured the exercise-side settings that keep Gradle from forking a daemon (A.4.4). The revision was reviewed over both plans in two rounds; the review found one stale dependency in A.12, and the reviewer then approved explicitly: "I approve, no remaining concerns."
