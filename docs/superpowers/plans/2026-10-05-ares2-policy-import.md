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
- The whole file must be valid UTF-8 (decision Q15). The reader checks it before the first line with `iconv -f UTF-8 -t UTF-8`, run in the C locale, and refuses the file, naming the first line that fails, when it holds an invalid or overlong sequence, an encoded surrogate, or a code point above U+10FFFF. Inside values and keys, control characters are refused: C0 (U+0000 to U+001F), DEL (U+007F) and C1 (U+0080 to U+009F), and the bidirectional formatting characters U+202A to U+202E and U+2066 to U+2069, which make a path read differently on a terminal from what it is. Every other code point is allowed, so a path with a non-ASCII name works; keys stay ASCII, since every key of the schema is. A comment may hold any valid UTF-8 except NUL, CR and tab. Messages quote such a value with `${value@Q}`, which shows it as it is in a UTF-8 locale and escapes it in the C locale.
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
user.home      = environment HOME
java.io.tmpdir = environment TMPDIR /tmp
```

- **`[base]`** names one or more base policy files, each of which must exist. One resolution rule, used everywhere in this plan: a bare file name (no slash) is resolved beside `phobos-policysystem.sh`, where today's `Base*.cfg` live; a name with a slash is resolved under `language-configurations/`, and `..`, an absolute path and a symbolic link leading out of either folder are refused. A run that imports an Ares policy folds exactly these bases and no other `Base*.cfg` (A.6), so a Java configuration runs under the Java base only (decision Q8) and a Maven configuration under the Maven base (decision Q7).
- **`[placeholders]`** names each placeholder this configuration supports and how Phobos determines its value itself (decision Q3), with three generic primitives and nothing else:
  - `environment <VARIABLE> [<fallback>]`: the variable's value in the environment `phobos.sh` was started in, or the fallback when it is unset or empty;
  - `command-ancestor <command> <levels>`: the command looked up on the `PATH` of that environment, resolved through every symbolic link with `realpath -e`, then that many directory levels up (`java` at `/opt/java/openjdk/bin/java` with 2 gives `/opt/java/openjdk`);
  - `fixed <absolute path>`: a constant.
  Every determined value must be an absolute path to a directory that exists, or the placeholder is refused, naming the configuration file and the primitive. The trust invariant, stated once and pinned by a test: a placeholder value is determined only from the environment and the `PATH` of the process that runs `phobos.sh`, from the image, and from the configuration file, all of which the grader sets before the command is started and none of which the submission can reach, since the specification is built before the command exists. Phobos never reads the command's environment, its current directory, or any file of the assignment tree to determine a value. A grading setup that hands `phobos.sh` an environment the submission influenced breaks this invariant; SECURITY.md states it as an integration requirement beside the existing one for the exercise configuration. The value is written to the debug log.
- `${PROJECT_ROOT}` is not a language matter and is not configured here (A.5.2 step 6).
- A configuration name with no file is refused: "the programming language configuration 'X' has no file 'language-configurations/X.cfg' beside phobos-policysystem.sh, so Phobos does not know which base policy it runs under". A future Ares configuration for another language therefore needs a data file and a base policy, never a code change.
- The eight Java files differ only in `[base]`. The four `GRADLE` ones name today's `BaseLanguage-java.cfg`, which was pruned on a Gradle exercise; it keeps its name, so the matrix, the acceptance suites, the documentation and every operator's run are untouched. The four `MAVEN` ones need a base pruned on a Maven reference exercise (A.11, pull request 5). Until that base exists, the four `MAVEN` configuration files are not shipped, so a Maven policy is refused with the missing-configuration message instead of failing late with `EACCES` on `~/.m2` (decision Q7).
- Where the Maven base lives is decided in pull request 5, with one constraint fixed now: a run without an Ares policy folds every `Base*.cfg` beside `phobos-policysystem.sh`, as today, so a second Java base must not sit there, or every `.cfg`-only run in the image would gain the Maven grants without a word. The Maven base therefore lives in `language-configurations/bases/`, which the `Base*.cfg` glob does not reach, and a `[base]` entry may name a file there (`bases/BaseLanguage-java-maven.cfg`). A `[base]` entry is resolved against the folder of `phobos-policysystem.sh` for a bare name and against `language-configurations/` for a name with a slash, and nothing else.

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

- A `udp` rule with a concrete port is a Landlock `--connect-udp` rule, which needs Landlock version 10 (Linux 7.2). Below that the enforcer refuses the run with status 125 rather than leave UDP unenforced, unless a `udp` loopback rule with no port sits beside it, in which case the connect guard alone holds it (PR 159). A `udp` loopback rule with no port itself (an Ares entry on `localhost` or a loopback address with port 0) needs no Landlock rule and runs on any kernel. The shipped Java base has TCP loopback rules only, so on the kernels the CI runners have today (6.17 and 7.0) **an Ares policy with a granted network entry that names a port is refused with status 125**, unless one of its own entries is a loopback entry with port 0. This is fail closed, and it is the consequence of decision Q6 as it stands; Remaining question R1 asks whether to keep it.
- A `udp` rule that names a DNS name is resolved once, before the command starts, through `--resolver`, and held to the addresses it had then; without `--resolver` the run is refused (`PHB-ERUNTIME`).
- A `udp` rule brings the ephemeral UDP bind grant (`--ephemeral-bind-udp`) with it, as every `udp` `[connect]` rule does.

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
- **Base selection.** Before it folds any base, `phobos-policysystem.sh` reads the configuration name of every `.yaml`/`.yml` `--config` file (with the YAML reader, so a malformed file is refused at this point already) and loads its programming language configuration file. When there is none, the bases are every `Base*.cfg` beside the script, exactly as today. When there is one, the bases are exactly the files its `[base]` names, in the order written, and no other `Base*.cfg` is folded; a named base that does not exist is refused. Two Ares files that name different configurations are refused, even where their `[base]` lists agree, since one run has one base and one set of placeholder values. This is the only change to base discovery. It is a deliberate change of base chosen by data, not a guaranteed narrowing: a configuration that names a top-level base folds a subset of what a `.cfg`-only run folds, but one that names a base under `language-configurations/bases/` (the Maven base of pull request 5) folds grants that no `.cfg`-only run in the same image gets. The pull request that ships such a base states what it permits, in the words AGENTS.md asks for. What base selection can never do is add a base the configuration does not name, or let a `.cfg`-only run reach a base under `language-configurations/`.
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
- **Nothing the policy permits is dropped without a word.** Every narrowing (no exemption for test classes, unmapped domains, an empty timeout list) produces a notice and is documented. Every combination Phobos could only approximate is refused.
- **No guessed translation.** `*` paths, `*` with port 0, a non-loopback host with port 0, partial network flags, unknown placeholders, a relative path or `${PROJECT_ROOT}` with no project root, a missing path, and every ambiguous YAML scalar are refused.
- **Same checks as a `.cfg`.** Translated lines go through `refuse_relative_path`, `refuse_wildcard_path`, `refuse_missing_path`, `append_connect_rule` (with `refuse_wildcard_host_name`, `refuse_malformed_address`, `refuse_unusable_port`), `set_parsed_timeout`, `refuse_unenforceable_network_rules` and the filesystem layer's `resolve_rights_hierarchy`. The importer adds checks; it removes none.
- **The covered-entry skip cannot widen.** It only leaves out an imported row whose right on that path the base already grants on the same resolved target or a resolved ancestor; it never adds a row and never edits a merged file, so no base or `.cfg` row can be lost.
- **Narrowness inside the base is not enforced by Phobos.** That is the additive model, unchanged; the summary line says so for each file, and the documentation states it next to the mapping table.
- **Trusted input.** An Ares policy grants access exactly as an exercise `.cfg` does, so SECURITY.md's integration requirement extends to it: the file given to `--config` must come from the instructor's test repository, never from the student's assignment tree, which a submission controls. In Artemis builds a `security-policy.yaml` usually sits in the test repository's `src/test/resources`; a grading script that searches the merged working tree for it could pick a student's copy. SECURITY.md gains this sentence.
- **No new attack surface in the image.** No package or interpreter is added; the reader is bash already present.
- **Placeholders and the project root are operator input.** Their values come from the environment `phobos.sh` was started in, the image, the programming language configuration, the `--project-root` flag and the tail flags, all set before the command runs and out of the submission's reach; each must be an absolute, existing directory, and each is written to the debug log.
- **The UDP floor is part of the import, not a later caveat.** Every granted network entry becomes a `udp` rule as well (decision Q6), and a `udp` rule with a port needs Landlock version 10 unless a `udp` loopback rule with no port sits beside it. Below version 10 the enforcer otherwise refuses the run with status 125, so on the kernels the CI runners and Docker Desktop have today an Ares policy with a granted entry that names a port cannot run, unless it carries a loopback entry with port 0 as well (A.5.3). That is the behaviour as decided, pending R1. The import never drops the `udp` rule to make such a run start, and never writes it only where the kernel happens to support it: the specification does not depend on the kernel.
- **Base selection follows the data and nothing else.** A run with an Ares policy folds exactly the bases its configuration names. For a top-level base that is a subset of what a `.cfg`-only run folds; for a base under `language-configurations/bases/` it is a different base, whose grants the pull request shipping it states explicitly. A `.cfg`-only run never reaches a base under `language-configurations/`.
- **No language in the code.** The loader and the importer contain no language name; a reviewer checks every pull request of this plan for it, and a test greps the scripts under `core/` (the data folder `core/config/` excepted) for `JAVA_USING`, `java.home`, `user.home` and `java.io.tmpdir` to prove it. Examples and comments elsewhere in the core may keep naming Gradle, as they do today; logic may not.
- **Parser divergence.** The subset refuses every construct whose meaning differs between YAML readers, so where Phobos and Ares could disagree on a value, Phobos refuses; for every field Phobos maps, it can be stricter than Ares, never laxer. For the fields it does not map it checks less than Ares (A.5.1), which cannot widen anything, since they grant nothing.

## A.9 Tests, both directions

| Level | Suite | Permitted direction | Forbidden direction |
| --- | --- | --- | --- |
| Unit | `tests/unit/phobos-tools-policysystem/yaml_subset.sh` (new) | every accepted construct of A.4.1 produces the exact records, both sequence indentations, `[ ]`, `{}`, both quote styles, comments | every refused construct produces `PHB-EPOLICY` with the right line: anchors, aliases, tags, block scalars, flow items, multi-documents, duplicates, tabs, CR, BOM, NUL, ambiguous booleans and numbers, bad escapes, continuation lines |
| Unit | `tests/unit/phobos-tools-policysystem/ares_policy.sh` (new) | the documented example policy and the two example policies of the Ares repository (rewritten as fixtures here, not copied) produce the expected `.paths`, `net.rules` and timeout; each field of A.5 maps as the table says; ms conversion of 1, 999, 1000, 1500, 120000, the 15-digit-seconds boundary | each "refused" cell of A.5 is refused with its message; a policy that would map to nothing but notices still parses |
| Integration | `tests/integration/ares_policy_program.sh` (new, a step in `test.yml`) | `phobos-policysystem.sh --config x.yaml` writes the specification; the result equals a hand-written `.cfg` with the same meaning; the covered-entry skip lets `allowed.txt` under the base's project tree pass; a `.cfg` and a `.yaml` given together merge additively, with the same result in either order; timeout min within a file, max across files | the skip never removes a base row (the `/usr/bin` case of `filesystem_policy.sh`), never skips a row whose ancestor is only lexical (a symbolic link fixture) or missing, a relative path is never resolved against the current directory of the caller or of the policy file (run from another directory, with neither `--project-root` nor a tail `--chdir`, it is refused), a misnamed file is refused by both readers, a strict-subset `.cfg` row is still refused when an Ares file is present |
| Integration | `tests/integration/malformed_cfg.sh` (extended) | | the file-level refusals (unreadable, BOM, NUL, CR, invalid UTF-8) for a `.yaml` name, with the same messages |
| Unit | `tests/unit/phobos-tools-policysystem/language_configuration.sh` (new) | a configuration file with `[base]` and the three primitives loads; `environment` with and without fallback, `command-ancestor` through a chain of symbolic links, `fixed`; a `[base]` entry with a slash resolves under `language-configurations/` | an unknown section or primitive, a value that is not an absolute existing directory, a command not on the `PATH`, a `[base]` entry with `..`, a missing file, CR, BOM and NUL are refused with file and line |
| Integration | `tests/integration/ares_policy_program.sh` (more cases) | a policy naming a configuration folds only its `[base]`, while a `.cfg`-only run in the same core still folds every `Base*.cfg`; `${java.home}` in a path resolves to the directory the configuration determines; `--project-root` overrides the tail's `--chdir` for relative paths and `${PROJECT_ROOT}`; `createAllFiles` with `deleteAllFiles` writes `[restructure]`; a granted network entry writes a TCP and a `udp` rule | two Ares files naming different configurations (also with the same `[base]`), a configuration with no file, a `--project-root` that is relative or missing, a placeholder the configuration does not name |
| Unit | `tests/unit/phobos-tools-policysystem/no_language_in_code.sh` (new) | | no script under `core/` outside `core/config/` contains `JAVA_USING`, `java.home`, `user.home` or `java.io.tmpdir` |
| Matrix | `tests/integration/protection-matrix/policy-syntax.sh` (extended) | every accepted Ares shape is accepted with status 0 | every refused Ares shape is refused with status 11 |
| Matrix | `tests/integration/protection-matrix/filesystem.sh` (extended) | a path granted only by an imported `readAllFiles` is readable, one granted `overwriteAllFiles` is writable | a sibling path the import does not name is denied, a file under an `executeAllFiles: false` entry is not executable, an all-false entry grants nothing, with the usual unprotected control and layer-off run |
| Matrix | `tests/integration/protection-matrix/network.sh` (extended) | an imported loopback rule with a concrete port connects over TCP, and on a Landlock version 10 kernel a datagram to the same port goes | another port on the same host is refused for both transports; below version 10 the run with an imported `udp` rule is refused with status 125, with control and layer-off run |
| Matrix | `tests/integration/protection-matrix/timeout.sh` (extended) | a 1500 ms Ares timeout ends a sleeping run at 1.5 s, not at 1 s or 2 s | |

## A.10 Documentation

- `README.md`, "Configuration format": a new subsection "Ares 2 policy files" with how detection works, the mapping table of A.5 in short form, the refusals, the narrowings and the "Phobos adds, Ares narrows" sentence.
- `core/phobos-tools-policysystem/config_doc.txt`: a fourth chapter, "4. What an Ares 2 policy becomes", with the full mapping of A.5.
- `core/phobos-policysystem.sh` and `core/phobos.sh` `--help`: one paragraph under `--config` on the extension rule.
- `SECURITY.md`: the trusted-input sentence of A.8.
- `CLAUDE.md` and `README.md` project structure: the three new files under `phobos-tools-policysystem/` and the folder `core/config/language-configurations/`.
- `README.md` and `--help`: `--project-root`, and the programming language configuration files, with the three primitives, as the one place where a language enters Phobos.
- `tests/README.md`: the new suites and the extended ones.
- If pull request #122 (Docusaurus) has merged by then: a page `documentation/docs/user/policy-reference/ares-2-policy.md` beside the section pages, and a cookbook entry; otherwise the README is the reference and the page is a follow-up.

## A.11 Pull requests, in order

Each is based on the one before (a stack); per AGENTS.md, a stacked pull request gets its workflows started with `workflow_dispatch`.

1. **`feature/ares2-yaml-subset-reader`**: `phobos-policy-yaml.sh` and `yaml_subset.sh`, with the strict UTF-8 check, sourced but not yet called. A pure function with a complete test table. No behaviour change.
2. **`feature/ares2-language-configurations`**: `phobos-language-configuration.sh`, the three primitives, the four `GRADLE` configuration files naming `BaseLanguage-java.cfg`, the lines in the run-phase Dockerfile and `assemble-run-phase-context.sh` that ship the folder, `language_configuration.sh` and `no_language_in_code.sh`. Loaded but not yet used. No behaviour change.
3. **`feature/ares2-policy-filesystem-and-timeout`**: `phobos-policy-ares.sh` with the whole schema check, the configuration lookup, base selection, placeholders, `--project-root`, the file system and timeout mappings (`[create-symlink]` and `[restructure]` included), the unmapped-domain notices, the covered-entry skip, the extension dispatch in `fold_cfg_into`, and a refusal of any non-empty `regardingNetworkConnections` ("not yet imported"), so the intermediate state fails closed. Unit, integration and matrix tests for those domains; README, `config_doc.txt`, `--help`, SECURITY.md. The body states what it now permits (symbolic links and moves under an imported `createAllFiles`).
4. **`feature/ares2-policy-network`**: the network mapping of A.5.3, TCP and UDP, replaces the interim refusal; matrix `network.sh` additions; documentation extended. The body states that an imported network entry now permits UDP as well.
5. **`feature/ares2-maven-base`**: a Maven reference exercise, its pruned base in `language-configurations/bases/`, and the four `MAVEN` configuration files. Depends on a pruner that can prune a Maven build (the prune plan of pull request 162, or the current pruner run on a Maven exercise).
6. **`feature/ares2-policy-docs-site`** (only if #122 has merged): the Docusaurus page and cookbook entry.

## A.12 Risks

- **Schema drift.** Ares may add a field, a domain or a version 2. Mitigated by refusing unknown keys and any version but 1, and by pinning the Ares commit in `ares_policy.sh`'s header; a change in Ares then shows up as a refusal, not a silent misreading. A weekly job that runs Ares's example policies through the importer is possible later; not in scope.
- **Ares's own Phobos writer** keeps emitting a format Phobos refuses. Harmless while Ares does not dispatch it, confusing to a reader; outside this repository (decision Q1).
- **Ares timeout semantics.** A policy written for Ares with `timeout: 3000` bounds the whole Gradle build at 3 s under Phobos, which no build survives. The example policies in the Ares repository do exactly that. Imported anyway by decision Q4; the summary line names the timeout.
- **UDP below Landlock version 10.** By decision Q6 every imported network entry brings a `udp` rule, which the enforcer refuses below version 10 unless a `udp` loopback wildcard sits beside it. On today's runner kernels an Ares policy with a granted entry that names a port, and no loopback entry with port 0 beside it, therefore fails closed with status 125 (R1).
- **No Maven base yet.** Until pull request 5, a `MAVEN` policy is refused for want of its configuration file, which is clear and early, but means Maven exercises cannot use the import.
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

And the standing rule: nothing may endanger Phobos's independence of programming languages; whatever depends on a language is done only on the basis of the programming language configuration.

Remaining questions:

- **R1.** With Q6, an Ares policy with a granted network entry that names a port, and no loopback entry with port 0 beside it, is refused with status 125 on a kernel below Landlock version 10, which includes every CI runner and Docker Desktop today. Keep that (fail closed until the runners reach Linux 7.2), or let a programming language configuration add a `udp` loopback rule with no port to its base, so that the connect guard alone holds the imported `udp` rules on older kernels, as PR 159 allows?
- **R2.** Where does the Maven reference exercise for pull request 5 come from?

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

expected=$'1\t.\tmap\t\n1\t.s\tstr\tit'"'"'s\n2\t.t\tstr\ta\\b"c'
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
  text="${case%%|*}"
  needle="${case##*|}"
  result="$(printf '%b\n' "$text" | records_of)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${needle}"* && "${result#*|}" == *"line "* ]]; then
    ok "refused, saying '${needle}' and a line: ${text}"
  else
    bad "refused, saying '${needle}' and a line: ${text}" "status ${PHB_EPOLICY}" "${result}"
  fi
done
for bytes in 'a:\t1\n' '\xef\xbb\xbfa: 1\n' 'a: 1\x00\n'; do
  result="$(printf "$bytes" | records_of)"
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
# Prints the YAML type of one plain scalar, "bool", "null", "int" or "str", and refuses one that
# YAML readers resolve differently (a boolean-like word other than true and false, or a spelling a
# YAML 1.1 reader takes for a number). Takes the scalar. Assumes PARSE_LOCATION names its line and
# that it is called plainly, so that a refusal ends the run.
yaml_plain_type() {
  local text="$1"
  case "$text" in
    true|false) printf 'bool'; return 0 ;;
    ""|"~"|null|Null|NULL) printf 'null'; return 0 ;;
  esac
  if [[ "${text,,}" =~ ^(true|false|yes|no|on|off|y|n)$ ]]; then
    refuse_cfg "${text@Q} is read as a boolean by some YAML readers and as a string by others; write true or false, or quote it"
  fi
  if [[ "$text" =~ ^(0|[123456789][[:digit:]]*)$ ]]; then
    printf 'int'
    return 0
  fi
  if [[ "$text" =~ ^[-+.]?[[:digit:]] || "${text,,}" =~ ^[-+]?\.(inf|nan)$ ]]; then
    refuse_cfg "${text@Q} is ambiguous: YAML readers disagree on whether it is a number. Write a plain whole number without sign or leading zero, or quote it"
  fi
  printf 'str'
}
```

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
- Produces: `load_language_configuration <name> <home>`, which sets `LANGUAGE_CONFIGURATION_BASES` (an array of absolute base file paths) and `LANGUAGE_CONFIGURATION_PLACEHOLDERS` (an associative array from placeholder name to its determined value), or refuses; `language_configuration_exists <name> <home>`.

- [ ] **Step 1: Write the failing tests.** In `language_configuration.sh`, a temporary home with a `language-configurations/` folder and a fake command on a `PATH` of its own (`${WORK}/bin/tool -> ${WORK}/opt/tool/bin/tool`, a symbolic link chain), then: `environment HOME` gives `$HOME`; `environment UNSET_VARIABLE /tmp` gives `/tmp`; `command-ancestor tool 2` gives `${WORK}/opt/tool`; `fixed /srv` gives `/srv`; a `[base]` entry `BaseLanguage-x.cfg` resolves beside the home and `bases/BaseLanguage-y.cfg` under `language-configurations/`. Refused, each with file and line: an unknown section, an unknown primitive, `command-ancestor missing 2`, a value that is not an existing directory, a relative `fixed`, a `[base]` entry with `..`, a base that does not exist, CR, BOM, NUL. In `no_language_in_code.sh`, one check that `grep -rn -E 'JAVA_USING|java\.home|user\.home|java\.io\.tmpdir' core --exclude-dir=config` finds nothing.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement** the loader as small documented functions, one per primitive (`determine_by_environment`, `determine_by_command_ancestor`, `determine_fixed`), each refusing through `refuse_cfg`; no language name anywhere.
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
- Produces: `parse_ares_policy <file> <project_root> <base_dir>`, which sets `PARSED_FS_DIR`, `PARSED_NET_FILE`, `PARSED_BIND_FILE`, `PARSED_ACCEPT_FILE`, the `PARSED_*` limits, `PARSED_ARES_CONFIGURATION` and `PARSED_ARES_SKIPPED`, and expands placeholders from `LANGUAGE_CONFIGURATION_PLACEHOLDERS`; `ares_row_covered_by_base <section> <path> <base_dir>`, which succeeds when the covered-entry skip of A.6 applies; `tail_flags_working_directory <tail_flags_file>`, which prints the last `--chdir` value of the tail flags or nothing; `ares_millis_to_timeout <digits>`, which prints the exact seconds with three decimals.

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
- Test: `tests/unit/phobos-tools-policysystem/ares_policy.sh`, `tests/integration/ares_policy_program.sh`, `tests/integration/protection-matrix/network.sh`, `policy-syntax.sh`
- Modify: `README.md`, `config_doc.txt`

**Interfaces:**
- Consumes: `append_connect_rule`, `is_ipv4_literal`, `is_ipv6_literal`.
- Produces: `ares_network_rule_line <host> <port>`, which prints the `allow ...` line of A.5.3 or refuses; `ares_map_network_entry` hands it to `append_connect_rule` twice, once as it is and once with ` udp` appended.

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

and the refusals: `example.org` with 0, `*` with 0, `example.org.` with 443, `70000`, each partial flag combination (six of them); in the matrix, an imported `localhost` rule on the probe server's port connects, the next port is refused for both transports, a datagram to the same port goes on a Landlock version 10 kernel and the run is refused with status 125 below it, each with control and layer-off run.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement** `ares_network_rule_line` and `ares_map_network_entry`, which calls `append_connect_rule "$(ares_network_rule_line "$host" "$port")" "$net"` with `PARSE_LOCATION` naming the entry's line, and remove the interim refusal of Task 3.
- [ ] **Step 4: Run** the unit, integration and matrix suites and the linters; all pass.
- [ ] **Step 5: Commit** `Translate the network domain of an Ares 2 policy into [connect] rules for TCP and UDP`.

## Pull request 5: the Maven base

### Task 6a: A Maven reference exercise and its base

- [ ] **Step 1:** Add a Maven reference exercise (R2) to the prune inputs and prune it with the pruner of the day.
- [ ] **Step 2:** Commit the result as `core/config/language-configurations/bases/BaseLanguage-java-maven.cfg` and the four `MAVEN` configuration files naming `bases/BaseLanguage-java-maven.cfg`.
- [ ] **Step 3:** Extend `ares_policy_program.sh`: a `MAVEN` policy folds only the Maven base, and a `.cfg`-only run in the same core still folds only the top-level `Base*.cfg`, never the Maven base.
- [ ] **Step 4:** Commit `Add the Maven base and the Maven programming language configurations`.

## Pull request 6 (only if #122 has merged): the documentation site

### Task 7: Docusaurus page

**Files:**
- Create: `documentation/docs/user/policy-reference/ares-2-policy.md`, `documentation/docs/user/policy-cookbook/importing-an-ares-2-policy.md`

- [ ] **Step 1:** Write the page from A.5 and A.8, in the shape of the neighbouring section pages.
- [ ] **Step 2:** Build the site as #122's workflow does (`pnpm install --frozen-lockfile` and `pnpm build` in `documentation/`) and check the page renders and its links resolve.
- [ ] **Step 3:** Commit `Document the Ares 2 policy import on the documentation site`.

---

## Review record

The first version was reviewed in a four-round review dialogue; that review replaced a post-merge edit of the merged rows with the import-time covered-entry skip against the base, made the skip resolve with `realpath -e`, added the case-by-case YAML contract table, stated the working-directory integration requirement, and narrowed the schema-fidelity claim. After the owner's decisions of 2026-10-05 the plan was revised (programming language configuration files, base selection by configuration, `--project-root`, placeholders, `[restructure]`, UDP, strict UTF-8 in place of the earlier ASCII-only rule) and reviewed again in five rounds, which aligned the project-root rule of A.5.2 step 6 with Part B and the tests of Part B with A.9; the reviewer approved the revision explicitly after the fifth round.
