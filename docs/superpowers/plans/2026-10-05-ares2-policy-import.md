# Ares 2 Policy Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `phobos.sh --config` take an Ares 2 `security-policy.yaml` beside the existing `.cfg` files, translate every element of it that Phobos can enforce into the same specification a `.cfg` produces, and refuse, with file and line, every element whose translation would widen or narrow the sandbox without saying so.

**Architecture:** A strict YAML subset reader in bash turns the policy into flat, typed records with line numbers. An Ares importer checks those records against the Ares 2 schema (version 1), maps the file system, network and timeout domains onto the existing `.cfg` internals (so every translated value passes the same refusals a hand-written `.cfg` line passes), and reports the domains Phobos has no equivalent for. `phobos-policysystem.sh` picks the reader by file extension and folds the result through the existing additive merge as an exercise configuration. No new language, no new package and no new flag is added to the run-phase image.

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

Ares 2 already contains a Phobos writer, `JavaPhobosTestCase.writePhobosSecurityTestCaseFile`, which emits `[readonly]`, `[write]`, `[network]` with `deny *`, and `[limits]`. Phobos refuses all four of those today (`[readonly]`, `[network]` and the `deny` line are unknown), and Ares never dispatches the result. This plan does not depend on that writer; whether to retire it is Open Question Q1.

## A.2 What Phobos is, and why an import can only add

Phobos confines the whole process tree a grading command starts: Gradle or Maven, the JVM, the JDK, the test framework, the test classes and the student code alike. Ares confines the student package inside the JVM and exempts the test classes and its own infrastructure. An Ares policy that grants "read `allowed.txt`" means "the student code may read that one file and nothing else", but a Gradle build cannot run at all with that alone, which is why the shipped `BaseLanguage-java.cfg` grants the whole project tree, the JDK and `/root/.gradle`.

So an imported policy is folded on top of the base, as every `--config` file is. It adds what it grants beyond the base, and it cannot express "nothing else": a narrowness that lies inside the base stays Ares's job in the JVM. This is the existing, deliberate model (AGENTS.md: "Do not 'fix' the union back to a narrow-only exercise merge"), and the import makes it loud rather than hiding it: see A.6, the covered-entry skip, and the summary line in A.7.

## A.3 Approaches considered

1. **A strict YAML subset reader in bash inside the policy system (chosen).** No new runtime dependency in the run-phase image, whose `/usr` the base grants `rx` to the submission, so every interpreter added there is one the student code can run too. The reader knows the line of every value, so `refuse_cfg` messages carry file and line naturally. It refuses every YAML feature outside the subset, so it can be wrong only by refusing, never by reading a value differently from Ares. Cost: a few hundred lines of bash and a careful test suite.
2. **A Python helper with PyYAML in the run-phase image.** Full YAML, less code. Rejected for v1: it adds Python and a third-party package to the image the submission runs in, PyYAML's YAML 1.1 resolution differs from Jackson's in places (`yes`, sexagesimals), so it would still need the same type rules, and line numbers need the lower-level event API.
3. **Ares emits the current `.cfg` format and Phobos keeps reading only `.cfg`.** The schema then lives in exactly one place, Ares's Jackson validator, and Phobos gains nothing to maintain. Not chosen because Markus asked for Phobos to read the YAML, but it is a real alternative with a lower drift risk, recorded as Open Question Q1.

A fourth shape, an offline converter that writes a reviewable `.cfg`, is not needed: `phobos-policysystem.sh --debug` already prints the effective specification, which is what such a converter would show.

## A.4 Where the parsing lives

| Concern | Decision |
| --- | --- |
| Format detection | By file extension inside `fold_cfg_into` in `core/phobos-policysystem.sh`: a `--config` file whose name ends in `.yaml` or `.yml` is read by the Ares importer, every other name by `parse_cfg_policy` exactly as today. Both readers fail closed on the other format (a YAML file has content before any `[section]`; a `.cfg` has no YAML root keys), so a misnamed file is refused, never misread. No new flag is added, so `phobos.sh` and the standalone `--config` of every layer script work unchanged, because each already hands its `--config` files to `phobos-policysystem.sh`. The base policy is still only `Base*.cfg`; an Ares policy is always an exercise configuration. Alternative recorded as Q14. |
| YAML reader | New file `core/phobos-tools-policysystem/phobos-policy-yaml.sh`, function `read_yaml_subset`, sourced by `phobos-common.sh` after `phobos-policy-parse.sh`. |
| Ares schema and mapping | New file `core/phobos-tools-policysystem/phobos-policy-ares.sh`, function `parse_ares_policy`, sourced after the YAML reader. It writes the same outputs `parse_cfg_policy` writes (`PARSED_FS_DIR`, `PARSED_NET_FILE`, `PARSED_BIND_FILE`, `PARSED_ACCEPT_FILE`, the `PARSED_*` limits) plus `PARSED_ARES_LANGUAGE` and `PARSED_ARES_SKIPPED`, the number of rows the covered-entry skip left out. |
| Image | No Dockerfile change: `docker/run_phase/java/Dockerfile` already copies the whole `phobos-tools-policysystem` folder. No package is added. |
| Shell | bash, as every file in `core/phobos-tools-policysystem/` is, and as `refuse_cfg` (which relies on `${var@Q}` and on ending the run) requires. |

### A.4.1 The YAML subset

The reader accepts exactly this, and refuses everything else with a message that names the construct and the line:

- One document. An optional `---` on the first significant line; a second `---` or any `...` is refused.
- Text with LF endings. A carriage return, a byte order mark, a NUL byte or a tab character anywhere is refused (tabs are not valid YAML indentation, and refusing them everywhere keeps the record format, which is tab-separated, unambiguous).
- Outside comments, only printable ASCII (bytes 0x20 to 0x7E) is accepted. Every key and every value the schema defines can be written in it, and it removes any question of how a malformed or unusual UTF-8 sequence would be decoded by Jackson and carried by bash. A comment may hold any other byte except NUL, CR and tab, since it carries no meaning. A path with a non-ASCII name is therefore refused in v1 (Q15).
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
| `-l` as a plain item | string | refused (plain scalar starting with an indicator); write `"-l"` |
| `::1` plain | string under SnakeYAML | refused (starts with an indicator); write `"::1"` |

The output is a records file, one line per node:

```
<line>\t<path>\t<type>\t<value>
```

where `<path>` is `.` for the root and `.key`, `[index]` steps below it (for example `.regardingTheSupervisedCode.theFollowingResourceAccessesArePermitted.regardingNetworkConnections[2].onThePort`), `<type>` is one of `map`, `seq`, `str`, `int`, `bool`, `null`, and `<value>` is empty for `map`, `seq` and `null`. Containers are recorded too, so an empty list is visible as a `seq` with no children.

## A.5 The mapping table

"Refuse" always means `refuse_cfg` with `PHB-EPOLICY`, the file, the line of the offending value, and the Ares field path. "Notice" means one line through `_log` on standard error, which is always printed, so nothing is dropped silently; notices are collected into the summary line of A.7.

### A.5.1 Root and supervised code

| Ares element | Phobos concept | Translation | What is refused |
| --- | --- | --- | --- |
| `thisPolicyFileCompliesToThePolicyVersion` | none, a format gate | Must be `int` `1`. | Absent, not an `int`, or any other value. |
| unknown key at any level | none | none | Always refused, as Ares refuses it. |
| `theFollowingProgrammingLanguageConfigurationIsUsed` | the base policy the run uses | Must match `^JAVA_USING_(MAVEN\|GRADLE)_(ARCHUNIT\|WALA)_AND_(ASPECTJ\|INSTRUMENTATION)$`. Sets `PARSED_ARES_LANGUAGE=java`. `phobos-policysystem.sh` then requires that a base named `BaseLanguage-java.cfg` is among the `Base*.cfg` it folded (Q8 covers `BasePhobos.cfg`). The build tool, analyser and weaving parts grant nothing and are written to the debug log. The check is a language gate only, not a build-tool guarantee: a `MAVEN` policy under the Gradle-pruned shipped base passes it and then fails late, with EACCES on `~/.m2`, which is fail closed but not an import-time refusal (Q7). No implicit grant is derived from any part: an agent jar, an AspectJ weaver or a Maven repository is reachable only if the base or an explicit entry grants it. | Absent, not a `str`, any value outside the eight (a future `PYTHON_USING_...` included, until a pull request adds it to this table), and a Java value when no `BaseLanguage-java.cfg` was folded. |
| `theSupervisedCodeUsesTheFollowingPackage` | none (a JVM concept) | Checked to be absent, `null` or a non-empty `str`; no grant. | Any other type, or an empty string. |
| `theMainClassInsideThisPackageIs` | none | As above. | As above. |
| `theFollowingClassesAreTestClasses` | none: Phobos confines the whole process, test classes included | Checked to be a `seq` of non-empty `str`. Notice: "test classes get no exemption from Phobos; what they need must come from the base or from an explicit entry". | Absent, not a `seq`, or an item that is not a non-empty `str`. |
| `theFollowingTestBehaviorIsConfigured` | none | Absent or an empty `map`. | `null` or any key inside it (Ares defines none). |
| `theFollowingResourceAccessesArePermitted` | the exercise allow-list | A `map` with exactly the six list keys, each a `seq`. | A missing list, an extra key, a list that is not a `seq`. |

The patterns Ares applies to package, class and thread names (`\p{javaJavaIdentifierStart}` and friends) are not re-implemented: those fields grant nothing at the operating-system level, and Ares refuses a bad value itself when it loads the same file. Q11 asks whether Phobos should mirror them anyway.

What Phobos checks, stated narrowly: the structure and the type of every field of the schema, and the value of every field it maps (the language, the file system, network and timeout fields). For the fields it does not map (package, main class, test classes, commands, thread and package entries) it checks structure, type and non-emptiness only, so it can accept a value there that Ares refuses; such a value grants nothing in Phobos, and Ares refuses the file when it loads it. Placeholders are expanded only in `onThisPathAndAllPathsBelow`. A `${` in the package, main class, test class, thread class, package import or host field is refused: Phobos does not expand placeholders there, and refusing is the conservative answer (with the default system properties every expansion contains a `/`, which none of those fields' patterns admits, so Ares refuses such a value as well, but an overridden property could expand differently). A `${` in a command is left alone, since commands grant nothing here.

### A.5.2 File system: `regardingFileSystemInteractions[i]`

| Ares field | Phobos section | Landlock rights | Notes |
| --- | --- | --- | --- |
| `readAllFiles: true` | `[read]` | READ_FILE, READ_DIR | |
| `overwriteAllFiles: true` | `[write]` | WRITE_FILE, TRUNCATE | Ares: "replacing the contents of existing files". |
| `createAllFiles: true` | `[create]` and `[create-symlink]` | MAKE_REG, MAKE_DIR, MAKE_SYM | Ares counts `createFile`, `createDirectory`, `createDirectories`, `createTempFile`, `createTempDirectory` and `createSymbolicLink` as create, so both sections hold exactly what Ares permits. `createLink` (a hard link) needs REFER across directories, which is not granted (Q9). |
| `executeAllFiles: true` | `[execute]` | EXECUTE | |
| `deleteAllFiles: true` | `[delete]` | REMOVE_FILE, REMOVE_DIR | |
| all five `false` | none | none | Ares's `createRestrictive(path)`; grants nothing in Ares either. No row is written. |
| never produced | `[create-ipc]`, `[restructure]` (REFER) | | Ares has no right for UNIX sockets or named pipes, and a cross-directory move is not one Ares right. A Java `Files.move` across directories is therefore denied by Phobos where Ares allows it: a narrowing, stated in the documentation and in Q9. |

`onThisPathAndAllPathsBelow` is turned into one absolute path, in this order, and refused at the first step that fails:

1. Must be a non-empty `str`.
2. `*` is refused: it would grant the rights on `/`, the whole file system, which a `.cfg` can say explicitly if it is really meant.
3. A backslash is refused (Ares treats it as a separator on Windows; on Linux it is part of a name).
4. Placeholders: `${PROJECT_ROOT}` is replaced by the run's working directory (step 6). `${java.home}`, `${user.home}` and `${java.io.tmpdir}` are refused in v1 with a message naming the absolute path to write instead, because Phobos has no JVM to ask and an environment variable is not a source it may trust for a boundary (Q3). Any other `${` is refused.
5. A `..` segment is refused, as Ares refuses it.
6. A relative path is made absolute against the run's working directory, which is what the JVM resolves it against in Ares (`Path.toAbsolutePath()`). `${PROJECT_ROOT}` is the same directory in practice: the reader only falls back to the policy file's parent directory when no root is given, and both callers give one, `JupiterSecurityExtension` with `projectFolderPath(Path.of("").toAbsolutePath())` and `SecurityPolicyReader.selectSecurityPolicyReader(path)` with `Path.of("").toAbsolutePath()`, the JVM's working directory. Gradle's `Test` task and Maven Surefire start the test JVM in the project directory by default. That directory is the value of the last `--chdir` in the tail flags, which is the directory `phobos-landlock-filesystem-and-networksystem` changes into before it runs the command (`TailPhobos.cfg` ships `--chdir /var/tmp/testing-dir`). If the tail flags fix no working directory, or fix a relative one, a relative path and `${PROJECT_ROOT}` are refused ("this run has no fixed working directory to resolve 'allowed.txt' against; write the absolute path"). This is an integration requirement, stated in the documentation and in SECURITY.md: the tail's `--chdir` must be the directory the build tool starts the test JVM in. A grading command that changes directory before it starts the build (`bash -c 'cd sub && ./gradlew test'`) breaks it, and then a relative Ares path names one file to Ares and another to Phobos. Neither the tail flags nor any flag can see the JVM's working directory, so no source is exact; both are operator input that a submission cannot change, so a mismatch is a misconfiguration, not an attack path. A suite pins that resolution follows `--chdir` and nothing else. Q2 asks whether an explicit flag is preferred, or whether relative paths should be refused altogether.
7. The resulting line goes through the existing `refuse_relative_path`, `refuse_wildcard_path` and, because an Ares policy is always an exercise configuration, `refuse_missing_path` for `[read]` and `[execute]`.
8. New for imports: the path must exist in every section, `[write]`, `[create]` and `[delete]` included. Ares does not say whether a path is a file or a directory, and the filesystem layer materialises a missing changeable path as an empty file (`materialise_write_path`), which for a path such as `target` would break the build that was meant to create a directory there. Q10 asks whether materialising as a file is preferred.

9. Before a (section, path) row is written, the covered-entry skip of A.6 decides whether the base already grants it; a covered row is counted and not written.

### A.5.3 Network: `regardingNetworkConnections[i]`

| `openConnections`, `sendData`, `receiveData` | Translation |
| --- | --- |
| all `true` | One `[connect]` rule for TCP, built as below. |
| all `false` | No rule (Ares's `createRestrictive(host, port)`). |
| any other combination | Refused. Phobos cannot let a connection be opened and forbid sending or receiving on it (config_doc.txt: "There is no `openConnections` / `sendData` / `receiveData` toggle"), and `openConnections: false` with `sendData: true` is Ares's unconnected datagram send, which Phobos would need a `udp` rule for. Granting the connection would permit more than the policy states; granting nothing would narrow without saying so. Q5. |

`onTheHost` and `onThePort` become an `allow` line, which is then handed to the existing `append_connect_rule`, so the address checks, the wildcard refusal and the port checks of a `.cfg` line apply unchanged and the merged-policy check `refuse_unenforceable_network_rules` judges it with every other rule:

| Ares host | `onThePort` 1..65535 | `onThePort` 0 (every port) |
| --- | --- | --- |
| `localhost` | `allow localhost:<p>` | `allow localhost` |
| IPv4 literal | `allow <a>:<p>` | `allow <a>:*`, which the merged-policy check accepts only for loopback and refuses otherwise |
| IPv6 literal, IPv4-mapped included | `allow [<a>]:<p>` | `allow [<a>]`, as above |
| DNS name | `allow <name>:<p>`, enforced by name by the egress broker; the network layer refuses it when no `--resolver` is given, as for a `.cfg` | refused: a host other than loopback must name a port |
| DNS name ending in `.` | refused with a hint to drop the dot (Q13) | refused |
| `*` | `allow *:<p>`, every host on that port, plus a notice naming it | refused |
| anything else | refused (Ares's `HOST_PATTERN` admits nothing else, so this is a backstop) | refused |

`onThePort` must be an `int` from 0 to 65535. Ares's `connect` covers both `java.net.Socket` and `java.net.DatagramSocket`; the import writes TCP rules only, so a datagram the Ares policy permits is denied by Phobos. That is a narrowing, logged once per run as a notice and documented (Q6 asks whether to also write a `udp` rule, which needs Landlock version 10 and, for a name, a resolver).

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
- An empty `regardingTimeouts` list writes no timeout, matching Ares's own Phobos writer (`collectResourceLimits` returns an empty map), with a notice. Q4 asks whether Ares's restrictive default of 10 s should be written instead, and whether a timeout that Ares means for the supervised code should bound the whole build at all.
- `mem_mb`, `nproc`, `nofile`, `fsize_mb` and `cpu` are never produced; their defaults and the base apply.

## A.6 Composition with the additive merge and the base

- `fold_cfg_into` calls `parse_ares_policy` instead of `parse_cfg_policy` for a `.yaml` or `.yml` file and then runs the same `fs_union_dir`, `net_union` and `merge_limits`. The file counts as an exercise configuration everywhere, so a run given only an Ares policy keeps its network rules (the "no `--config`" most restrictive shape is unchanged and still keyed on the number of `--config` files).
- After every configuration is folded, `phobos-policysystem.sh` checks `PARSED_ARES_LANGUAGE` against the base names (A.5.1).
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
Policy invalid: theFollowingProgrammingLanguageConfigurationIsUsed is JAVA_USING_GRADLE_WALA_AND_ASPECTJ, which needs the Java base policy BaseLanguage-java.cfg beside phobos-policysystem.sh, and the base folded here is 'BaseLanguage-python.cfg'. (PHB-EPOLICY)
```

The last one has no line because it is judged after every file is folded; it names the file through the message instead.

One summary line per imported file, always printed through `_log`:

```
Ares 2 policy 'security-policy.yaml' (JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ): 3 file system rows and 1 [connect] rule imported for TCP only; 2 entries already covered by the base, whose narrower intent Ares enforces in the JVM; not enforced by Phobos: 1 command, 0 thread and 2 package entries, and the test-class exemption.
```

## A.8 Security analysis

- **Nothing is permitted that the policy does not state.** Every grant comes from a field set to `true`, mapped to the right that field names in Ares. The only right added beyond the literal field name is `[create-symlink]` for `createAllFiles`, which is what Ares's own create category includes (A.5.2). This now permits creating a symbolic link under a path an Ares policy grants `createAllFiles` on, which a `.cfg` does not permit unless it names `[create-symlink]`; it is a property of the import, not a change to the `.cfg` format, and the pull request introducing it says so in those words.
- **Nothing the policy permits is dropped without a word.** Every narrowing (TCP only, no REFER, no exemption for test classes, unmapped domains, an empty timeout list) produces a notice and is documented. Every combination Phobos could only approximate is refused.
- **No guessed translation.** `*` paths, `*` with port 0, a non-loopback host with port 0, partial network flags, unknown placeholders, a relative path with no fixed working directory, a missing path, and every ambiguous YAML scalar are refused.
- **Same checks as a `.cfg`.** Translated lines go through `refuse_relative_path`, `refuse_wildcard_path`, `refuse_missing_path`, `append_connect_rule` (with `refuse_wildcard_host_name`, `refuse_malformed_address`, `refuse_unusable_port`), `set_parsed_timeout`, `refuse_unenforceable_network_rules` and the filesystem layer's `resolve_rights_hierarchy`. The importer adds checks; it removes none.
- **The covered-entry skip cannot widen.** It only leaves out an imported row whose right on that path the base already grants on the same resolved target or a resolved ancestor; it never adds a row and never edits a merged file, so no base or `.cfg` row can be lost.
- **Narrowness inside the base is not enforced by Phobos.** That is the additive model, unchanged; the summary line says so for each file, and the documentation states it next to the mapping table.
- **Trusted input.** An Ares policy grants access exactly as an exercise `.cfg` does, so SECURITY.md's integration requirement extends to it: the file given to `--config` must come from the instructor's test repository, never from the student's assignment tree, which a submission controls. In Artemis builds a `security-policy.yaml` usually sits in the test repository's `src/test/resources`; a grading script that searches the merged working tree for it could pick a student's copy. SECURITY.md gains this sentence.
- **No new attack surface in the image.** No package or interpreter is added; the reader is bash already present.
- **Parser divergence.** The subset refuses every construct whose meaning differs between YAML readers, so where Phobos and Ares could disagree on a value, Phobos refuses; for every field Phobos maps, it can be stricter than Ares, never laxer. For the fields it does not map it checks less than Ares (A.5.1), which cannot widen anything, since they grant nothing.

## A.9 Tests, both directions

| Level | Suite | Permitted direction | Forbidden direction |
| --- | --- | --- | --- |
| Unit | `tests/unit/phobos-tools-policysystem/yaml_subset.sh` (new) | every accepted construct of A.4.1 produces the exact records, both sequence indentations, `[ ]`, `{}`, both quote styles, comments | every refused construct produces `PHB-EPOLICY` with the right line: anchors, aliases, tags, block scalars, flow items, multi-documents, duplicates, tabs, CR, BOM, NUL, ambiguous booleans and numbers, bad escapes, continuation lines |
| Unit | `tests/unit/phobos-tools-policysystem/ares_policy.sh` (new) | the documented example policy and the two example policies of the Ares repository (rewritten as fixtures here, not copied) produce the expected `.paths`, `net.rules` and timeout; each field of A.5 maps as the table says; ms conversion of 1, 999, 1000, 1500, 120000, the 15-digit-seconds boundary | each "refused" cell of A.5 is refused with its message; a policy that would map to nothing but notices still parses |
| Integration | `tests/integration/ares_policy_program.sh` (new, a step in `test.yml`) | `phobos-policysystem.sh --config x.yaml` writes the specification; the result equals a hand-written `.cfg` with the same meaning; the covered-entry skip lets `allowed.txt` under the base's project tree pass; a `.cfg` and a `.yaml` given together merge additively, with the same result in either order; timeout min within a file, max across files | the skip never removes a base row (the `/usr/bin` case of `filesystem_policy.sh`), never skips a row whose ancestor is only lexical (a symbolic link fixture) or missing, the language check refuses under a Python base, a misnamed file is refused by both readers, a strict-subset `.cfg` row is still refused when an Ares file is present |
| Integration | `tests/integration/malformed_cfg.sh` (extended) | | the file-level refusals (unreadable, BOM, NUL, CR) for a `.yaml` name, with the same messages |
| Matrix | `tests/integration/protection-matrix/policy-syntax.sh` (extended) | every accepted Ares shape is accepted with status 0 | every refused Ares shape is refused with status 11 |
| Matrix | `tests/integration/protection-matrix/filesystem.sh` (extended) | a path granted only by an imported `readAllFiles` is readable, one granted `overwriteAllFiles` is writable | a sibling path the import does not name is denied, a file under an `executeAllFiles: false` entry is not executable, an all-false entry grants nothing, with the usual unprotected control and layer-off run |
| Matrix | `tests/integration/protection-matrix/network.sh` (extended) | an imported loopback rule with a concrete port connects | another port on the same host is refused, an imported TCP rule admits no datagram, with control and layer-off run |
| Matrix | `tests/integration/protection-matrix/timeout.sh` (extended) | a 1500 ms Ares timeout ends a sleeping run at 1.5 s, not at 1 s or 2 s | |

## A.10 Documentation

- `README.md`, "Configuration format": a new subsection "Ares 2 policy files" with how detection works, the mapping table of A.5 in short form, the refusals, the narrowings and the "Phobos adds, Ares narrows" sentence.
- `core/phobos-tools-policysystem/config_doc.txt`: a fourth chapter, "4. What an Ares 2 policy becomes", with the full mapping of A.5.
- `core/phobos-policysystem.sh` and `core/phobos.sh` `--help`: one paragraph under `--config` on the extension rule.
- `SECURITY.md`: the trusted-input sentence of A.8.
- `CLAUDE.md` and `README.md` project structure: the two new files under `phobos-tools-policysystem/`.
- `tests/README.md`: the new suites and the extended ones.
- If pull request #122 (Docusaurus) has merged by then: a page `documentation/docs/user/policy-reference/ares-2-policy.md` beside the section pages, and a cookbook entry; otherwise the README is the reference and the page is a follow-up.

## A.11 Pull requests, in order

Each is based on the one before (a stack); per AGENTS.md, a stacked pull request gets its workflows started with `workflow_dispatch`.

1. **`feature/ares2-yaml-subset-reader`**: `phobos-policy-yaml.sh` and `yaml_subset.sh`, sourced but not yet called. Reviewable on its own: a pure function with a complete test table. No behaviour change.
2. **`feature/ares2-policy-filesystem-and-timeout`**: `phobos-policy-ares.sh` with the whole schema check, the language check, the file system and timeout mappings, the unmapped-domain notices, the covered-entry skip, the extension dispatch in `fold_cfg_into`, and a refusal of any non-empty `regardingNetworkConnections` ("not yet imported"), so the intermediate state fails closed. Unit, integration and matrix tests for those domains; README, `config_doc.txt`, `--help`, SECURITY.md.
3. **`feature/ares2-policy-network`**: the network mapping of A.5.3 replaces the interim refusal; matrix `network.sh` additions; documentation extended.
4. **`feature/ares2-policy-docs-site`** (only if #122 has merged): the Docusaurus page and cookbook entry.

## A.12 Risks

- **Schema drift.** Ares may add a field, a domain or a version 2. Mitigated by refusing unknown keys and any version but 1, and by pinning the Ares commit in `ares_policy.sh`'s header; a change in Ares then shows up as a refusal, not a silent misreading. A weekly job that runs Ares's example policies through the importer is possible later; not in scope.
- **Ares's own Phobos writer** keeps emitting a format Phobos refuses. Harmless while Ares does not dispatch it, confusing to a reader (Q1).
- **Ares timeout semantics.** A policy written for Ares with `timeout: 3000` bounds the whole Gradle build at 3 s under Phobos, which no build survives. The example policies in the Ares repository do exactly that. Faithful to Ares's documentation ("the conversion happens once, where that configuration is written") but surprising (Q4).
- **Build tool mismatch.** A `MAVEN` policy under the shipped Gradle-pruned Java base fails with EACCES on `~/.m2` (fail closed, but late) (Q7).
- **Bash YAML reader correctness.** Mitigated by the subset's refuse-by-default design and a test table for every construct both ways.
- **Performance.** Policies are tens of lines; bash is adequate.
- **The covered-entry skip misunderstood as a hole.** Mitigated by the summary line and documentation; it is neutral for Landlock by construction and tested with the symbolic link and missing-ancestor cases.

## A.13 Open questions for Markus

- **Q1.** Should the translation live in Phobos at all, or should Ares's `JavaPhobosTestCase` be updated to emit the current `.cfg` format, so that the schema lives only in Ares? Either way, should the stale writer in Ares be retired?
- **Q2.** Relative paths and `${PROJECT_ROOT}` resolve against the tail flags' `--chdir`, which equals the JVM's working directory only while the grading command does not change directory. Keep that, prefer an explicit `--project-root` on `phobos.sh` (more flags, and just as unable to see the JVM's working directory), or refuse relative paths altogether (exact, but almost every existing Ares policy is written with relative paths)?
- **Q3.** Support `${java.home}`, `${user.home}`, `${java.io.tmpdir}`, and from what source (explicit flags, fixed values per base)? v1 refuses them.
- **Q4.** Ares's timeout bounds "the supervised code"; Phobos's bounds the whole build. Map it at all? If yes, keep the tightest within a file and the largest across files? Empty list: no timeout (as Ares's writer) or Ares's restrictive 10 s?
- **Q5.** Partial network flags are refused. Prefer granting the connection with a warning, leaving send and receive to Ares?
- **Q6.** Write TCP only, or also a `udp` rule (needs Landlock 10 and a resolver for names)?
- **Q7.** Introduce per-build-tool bases (`BaseLanguage-java-gradle.cfg`, `BaseLanguage-java-maven.cfg`) and check the build-tool part of the language value against them?
- **Q8.** Accept a Java Ares policy under `BasePhobos.cfg` (the cross-language union) as well as under `BaseLanguage-java.cfg`?
- **Q9.** `createAllFiles` adds `[create-symlink]`; should it also add `[restructure]` (REFER) when `deleteAllFiles` is set, so that `Files.move` across directories works as in Ares?
- **Q10.** Refuse a missing imported path in every section (v1), or materialise it as a file as a `.cfg` write path is?
- **Q11.** Mirror Ares's Java identifier patterns for package, class and thread names, so Phobos never accepts a file Ares refuses?
- **Q12.** Is the covered-entry skip acceptable, or would you rather have the strict-subset refusal also for imported rows, at the price of refusing most real policies?
- **Q13.** A DNS name with a trailing dot: refuse (v1) or strip the dot?
- **Q14.** Detect by extension (v1, and the same rule Ares's own `SecurityPolicyReader.selectSecurityPolicyReader` applies: `yaml` or `yml`) or by an explicit `--ares-policy` flag?
- **Q15.** Allow non-ASCII paths in v1, with strict UTF-8 validation, rather than refusing them?

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
  'a: ::1|indicator' 'a: "\xc3\xa4"|ASCII' 'a: 1:20|ambiguous' 'a: 8e1|ambiguous' 'a: +80|ambiguous' \
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
check "a leading document marker and comments, any bytes in a comment" "$expected" "$actual"

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

## Pull request 2: the Ares importer for the file system and the timeout

### Task 2: The schema check

**Files:**
- Create: `core/phobos-tools-policysystem/phobos-policy-ares.sh`
- Modify: `core/phobos-tools-common/phobos-common.sh` (source it after the YAML reader)
- Test: `tests/unit/phobos-tools-policysystem/ares_policy.sh`
- Modify: `.github/workflows/test.yml` (a step for the suite)

**Interfaces:**
- Consumes: `read_yaml_subset` (Task 1), `refuse_cfg`.
- Produces: `ares_check_schema <records>`, which refuses any record set that is not a valid version 1 policy per A.5.1 and the structural rows of A.5.2 to A.5.5; `ares_record_value <records> <path>` and `ares_record_line <records> <path>`, which print the value and the line of the record at a path, and print nothing when there is none.

- [ ] **Step 1: Write the failing test** with a fixture writer `policy_with()` that prints the documented example policy (A.1) with one line replaced, and a table of the form used in Task 1: the example passes; each of these fails with its message and line: version `2`, version `"1"`, a missing `regardingTimeouts`, an extra root key, `readAllFiles` missing, `readAllFiles: "true"`, `onThePort: "80"`, `theFollowingTestBehaviorIsConfigured: null`, `theFollowingTestBehaviorIsConfigured: {x: 1}`, a language `PYTHON_USING_PIP`, a language in lower case, a test class `""`, a command entry with an extra key, `createTheFollowingNumberOfThreads: "10"`, a `${user.home}` in the package, in a test class and in `onTheHost`; and a `${java.home}` in `executeTheCommand` is accepted.

```bash
for case in \
  'thisPolicyFileCompliesToThePolicyVersion: 1|thisPolicyFileCompliesToThePolicyVersion: 2|exactly 1' \
  '    regardingTimeouts:|    regardingTimeoutz:|unknown key' \
  '        readAllFiles: true|        readAllFiles: "true"|must be true or false' \
  '        onThePort: 80|        onThePort: "80"|whole number' \
  '  theFollowingProgrammingLanguageConfigurationIsUsed: JAVA_USING_MAVEN_WALA_AND_ASPECTJ|  theFollowingProgrammingLanguageConfigurationIsUsed: PYTHON_USING_PIP|not one of the eight'; do
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
ARES_LANGUAGE_PATTERN='^JAVA_USING_(MAVEN|GRADLE)_(ARCHUNIT|WALA)_AND_(ASPECTJ|INSTRUMENTATION)$'
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
- Produces: `parse_ares_policy <file> <tail_flags_file> <base_dir>`, which sets `PARSED_FS_DIR`, `PARSED_NET_FILE`, `PARSED_BIND_FILE`, `PARSED_ACCEPT_FILE`, the `PARSED_*` limits, `PARSED_ARES_LANGUAGE` and `PARSED_ARES_SKIPPED`; `ares_row_covered_by_base <section> <path> <base_dir>`, which succeeds when the covered-entry skip of A.6 applies; `tail_flags_working_directory <tail_flags_file>`, which prints the last `--chdir` value of the tail flags or nothing; `ares_millis_to_timeout <digits>`, which prints the exact seconds with three decimals.

- [ ] **Step 1: Write the failing tests**: for each row of A.5.2 a fixture with one entry under a temporary tree `${WORK}/proj` (created with `mkdir -p` and `: >`), and the expected content of each `.paths` file; `allowed.txt` relative with a tail file holding `--chdir ${WORK}/proj` becomes `${WORK}/proj/allowed.txt`; `${PROJECT_ROOT}/x` likewise; refusals for `*`, `a\\b`, `${java.home}/lib`, `${HOME}/x`, `../x`, `x/../y`, a relative path with a tail file without `--chdir`, a missing path under `overwriteAllFiles` only. And the conversion table:

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

The working directory:

```bash
# Prints the directory the enforcer changes into before it runs the command: the value of the
# last --chdir in the tail flags, which is the one phobos-landlock-filesystem-and-networksystem keeps. Prints nothing when
# the tail flags name none or the file is absent. Reads the tail flags as write_spec does, a "#"
# starting a comment and the rest split on white space. Needs no environment.
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

`ares_resolve_policy_path <value> <working_directory>` applies steps 2 to 6 of A.5.2 and prints the absolute path; `ares_map_file_entry <records> <index> <working_directory> <base_dir>` writes the sections of A.5.2, asking `ares_row_covered_by_base` before each row and counting the rows it leaves out in `PARSED_ARES_SKIPPED`; `ares_report_summary` prints the A.7 line. `parse_ares_policy` calls `read_yaml_subset`, `ares_check_schema`, the mappings in order, and, for this pull request, refuses a non-empty `regardingNetworkConnections` with "network permissions in an Ares 2 policy are not imported yet; this Phobos refuses the file rather than run without them".
- [ ] **Step 4: Run the suite and the linters**; all pass.
- [ ] **Step 5: Commit** `Translate the file system and timeout domains of an Ares 2 policy`.

### Task 4: Dispatch and language check in the policy program

**Files:**
- Modify: `core/phobos-policysystem.sh` (`fold_cfg_into`, the language check after the exercise loop, `--help`)
- Modify: `core/phobos-tools-policysystem/phobos-policy-ares.sh` (`refuse_ares_language_without_base`)
- Modify: `core/phobos.sh` (`--help` paragraph only)
- Test: `tests/integration/ares_policy_program.sh` (new), `tests/integration/malformed_cfg.sh` (extended)
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: `parse_ares_policy` and `ares_row_covered_by_base` (Task 3), `fs_union_dir`, `net_union`, `merge_limits`.
- Produces: `refuse_ares_language_without_base <language> <base_cfg>...`, which refuses a Java policy when no folded base is named `BaseLanguage-java.cfg`.

- [ ] **Step 1: Write the failing integration test** in the style of `policy_program.sh`: a temporary `core` copy with `BaseLanguage-java.cfg` beside `phobos-policysystem.sh`, a project tree under `${WORK}/proj` named in the base as `[read]`/`[execute]` and as the tail's `--chdir`, then:
  - an Ares file reading `allowed.txt` is accepted, `read.paths` does not contain `${WORK}/proj/allowed.txt` (skipped as covered), and standard error holds "already covered by the base";
  - an Ares file reading `${WORK}/outside/data.txt` (not under the base) is accepted and `read.paths` contains it;
  - the same file under a base renamed `BaseLanguage-python.cfg` is refused, naming the language and the base;
  - a symbolic link `${WORK}/proj/link -> ${WORK}/outside` with an Ares entry `link/data.txt` keeps `${WORK}/proj/link/data.txt` in `read.paths` (its resolved target is not under the project tree);
  - a base path that does not exist does not cover an imported path beneath it;
  - a base row `/usr/bin` beside `/usr`, with an Ares entry that also names `/usr/bin` read and execute, leaves the base's `/usr/bin` rows exactly as they were;
  - an exercise `.cfg` with `[read] ${WORK}/proj/allowed.txt` beside the Ares file is still refused by the filesystem layer's hierarchy check when the layer is run over the specification;
  - a `.yaml` and a `.cfg` given together merge, with byte-identical specifications in both orders: union of paths, largest timeout;
  - a run given only an Ares file keeps its `[connect]` rules (the no-`--config` shape does not apply);
  - a relative Ares path resolves against the tail's last `--chdir` and nothing else: the same policy with two tail files naming different directories gives two different absolute paths, and a tail with no `--chdir` refuses it;
  - `x.cfg` holding YAML and `x.yaml` holding a `.cfg` are both refused.
- [ ] **Step 2: Run it to see it fail.**
- [ ] **Step 3: Implement.** In `fold_cfg_into`:

```bash
  case "$cfg" in
    *.yaml|*.yml) parse_ares_policy "$cfg" "$tail_flags_file" "$base_dir" ;;
    *)            parse_cfg_policy "$cfg" "$exercise" ;;
  esac
```

The Ares branch is only reached from the exercise loop, since the base is only ever `Base*.cfg`; it appends `PARSED_ARES_LANGUAGE` to a list. After the exercise loop and before `refuse_unenforceable_network_rules`, call `refuse_ares_language_without_base` for each language seen, with the base file names. Nothing merged is edited afterwards.
- [ ] **Step 4: Run** `ares_policy_program.sh`, `policy_program.sh`, `filesystem_policy.sh`, `malformed_cfg.sh`, `limit_merge.sh` and the linters; all pass, none skipped.
- [ ] **Step 5: Commit** `Read an Ares 2 policy given to --config and fold it in as an exercise configuration`.

### Task 5: Matrix witnesses and documentation for pull request 2

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

## Pull request 3: the network domain

### Task 6: Network mapping

**Files:**
- Modify: `core/phobos-tools-policysystem/phobos-policy-ares.sh`
- Test: `tests/unit/phobos-tools-policysystem/ares_policy.sh`, `tests/integration/ares_policy_program.sh`, `tests/integration/protection-matrix/network.sh`, `policy-syntax.sh`
- Modify: `README.md`, `config_doc.txt`

**Interfaces:**
- Consumes: `append_connect_rule`, `is_ipv4_literal`, `is_ipv6_literal`.
- Produces: `ares_network_rule_line <host> <port>`, which prints the `allow ...` line of A.5.3 or refuses.

- [ ] **Step 1: Write the failing tests** for every cell of A.5.3:

```bash
for case in "localhost|80|allow localhost:80" "localhost|0|allow localhost" "127.0.0.1|0|allow 127.0.0.1:*" \
  "::1|443|allow [::1]:443" "::1|0|allow [::1]" "::ffff:127.0.0.1|8080|allow [::ffff:127.0.0.1]:8080" \
  "example.org|443|allow example.org:443" "*|443|allow *:443"; do
  host="${case%%|*}"
  rest="${case#*|}"
  port="${rest%%|*}"
  want="${rest#*|}"
  check "ares_network_rule_line ${host} ${port}" "$want" "$(ares_network_rule_line "$host" "$port")"
done
```

and the refusals: `example.org` with 0, `*` with 0, `example.org.` with 443, `70000`, each partial flag combination (six of them); in the matrix, an imported `localhost` rule on the probe server's port connects, the next port is refused, a datagram to the same port is refused, each with control and layer-off run.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement** `ares_network_rule_line` and `ares_map_network_entry`, which calls `append_connect_rule "$(ares_network_rule_line "$host" "$port")" "$net"` with `PARSE_LOCATION` naming the entry's line, and remove the interim refusal of Task 3.
- [ ] **Step 4: Run** the unit, integration and matrix suites and the linters; all pass.
- [ ] **Step 5: Commit** `Translate the network domain of an Ares 2 policy into [connect] rules`.

## Pull request 4 (only if #122 has merged): the documentation site

### Task 7: Docusaurus page

**Files:**
- Create: `documentation/docs/user/policy-reference/ares-2-policy.md`, `documentation/docs/user/policy-cookbook/importing-an-ares-2-policy.md`

- [ ] **Step 1:** Write the page from A.5 and A.8, in the shape of the neighbouring section pages.
- [ ] **Step 2:** Build the site as #122's workflow does (`pnpm install --frozen-lockfile` and `pnpm build` in `documentation/`) and check the page renders and its links resolve.
- [ ] **Step 3:** Commit `Document the Ares 2 policy import on the documentation site`.

---

## Review record

Reviewed in a four-round review dialogue before publication; the reviewer approved the plan explicitly in the fourth round. The review replaced a post-merge edit of the merged rows with the import-time covered-entry skip against the base, made the skip resolve with `realpath -e`, restricted values to printable ASCII, added the case-by-case YAML contract table, stated the working-directory integration requirement, and narrowed the schema-fidelity claim.
