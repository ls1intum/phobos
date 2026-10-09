# The pruners

Phobos has two pruners, and a third folder for what both need:

| Folder | What it is |
| --- | --- |
| `exercise_pruner/` | The layer pruner and the orchestrator. It prunes a reference exercise with its tests through the grading layers, and merges the results into one base per language. |
| `runtime_pruner/` | The recording pruner, `phobos-record`. It records a session of a program with no sandbox and turns it into a policy. |
| `shared/` | What both use: the policy model, the strace parser, attribution, generalisation, limits and the sampler. |

Each has `src/` and `test/`, and `test/` has `unit/` and `integration/`. Inside `src/`, and inside `test/unit/` and
`test/integration/`, the code is sorted into layers. A folder for a layer exists only where there is code for it.

| Layer | What belongs in it | Examples |
| --- | --- | --- |
| `domain` | The model and the rules. It may read files to judge a path, but it starts no process; the layering test enforces that by what it imports. | `cfgfile`, `generalise`, `limits`, `verdict`, `needs`, `names` |
| `infrastructure` | What touches the outside world: running a command, reading `/proc`, the kernel's audit records, a container's file system, the environment. | `runner`, `control`, `audit`, `sampler`, `observe`, `guard`, `snapshot` |
| `application` | One use case from start to end, which composes the layers below. | `stages`, `search`, `kvm`, `discovery`, `check`, `generate`, `diff` |
| `interface` | The command line, and the entry points. | `main`, `orchestrate`, `phobos-record` |

A module imports its own layer or a lower one, in the order domain, infrastructure, application, interface. `shared`
imports neither pruner, and the two pruners never import each other. `shared/test/unit/architecture/test_layering.py`
holds the code to this on every run.

A module is imported as `<package>.src.<layer>.<module>`, for example `shared.src.domain.cfgfile`, with `pruner/` on
the import path. Containers mount `pruner/` read-only at `/var/tmp/helpers`, so the entry points are
`/var/tmp/helpers/exercise_pruner/src/interface/main.py` and
`/var/tmp/helpers/runtime_pruner/src/interface/phobos-record`.

The suites source the harness of the protecter, `protecter/test/harness.sh`, whose contract and conventions are
described in [`protecter/test/README.md`](../protecter/test/README.md); a skipped check here is not a passing one
either, and the tables say what makes a suite skip.

The shell suites live under `pruner/<package>/test/integration/<layer>/`, the Python suites under
`pruner/<package>/test/unit/<layer>/`. A suite that runs in a container finds the harness the same way as on the
host, so the container mounts the repository's layout: `protecter/test` at `/repo/protecter/test`, `pruner` at
`/repo/pruner` and `protecter/src` at `/repo/protecter/src`, with `pruner` also at `/var/tmp/helpers`.

## Shell suites, run by `build.yml` and the manual workflows

The suites that need the prune image, a Docker network or a KVM guest. `layer_prune_observer.sh`,
`layer_prune.sh`, `layer_prune_egress.sh` and the record suites run inside the prune image that the
`run-phase` job of `build.yml` builds; `layer_prune_maven.sh` is run by `prune-maven.yml` and
`kvm_fixture_result.sh` by `prune-kvm.yml`.

| Suite | What it proves | Skips when |
| --- | --- | --- |
| `layer_prune_observer.sh` | run in the prune image: its base grants nothing and is accepted, strace sees a Landlock refusal inside the shipped chain while a granted read works, the parser and attribution turn the record into exactly that denial, and every policy the renderer writes is accepted by the parser while the strict subset it refuses is refused by `phobos.sh` too | never |
| `layer_prune.sh` | run in the prune image: the layer pruner prunes the fixture under `layer-prune-fixture/` end to end; the derived policy passes the fixture's build with every layer on, grants its `/proc/self/status` read as a per-run name, refuses what the build did not need (an unneeded file, an optional one, a prefix sibling, a write into what was read, `10.0.0.1:80`, port 8080), bounds each limit below its default with every containment check refused; the orchestrator merges the result, the fixture passes under the merged base and its own file, and a `.cfg` its record does not vouch for stops the merge; a flaky reference, NO-SOURCE, a needed `setsid`, a needed external host and a failure no refusal explains each abort without a policy | never; the nproc containment check is recorded unchecked as root, which the kernel exempts |
| `layer_prune_egress.sh` | run in the prune image, `--network none`: of two hosts the fixture declares, the one it needs keeps its rule and the other is dropped, with a stand-in resolver and TLS server on loopback; under the derived policy the egress broker closes a connect to the dropped host on the kept rule's port, the guard refuses it on any other port with `EACCES`, naming it in the ClientHello towards the kept host's address gets no answer, and a build that also needs an undeclared host aborts without a policy | never |
| `layer_prune_maven.sh` | run in the prune image of the JDK 25 run-phase image by the manual `prune-maven.yml`, not by `build.yml`: the image holds the manifest's bytes, the Maven reference exercise is pruned, merged and verified, its record shows both tests passed in every baseline run, every containment check refused, every grant under `/root` a single file and no write-class right there, and a copy without tests or with an absent version aborts and writes no policy | the image has no `/root/.m2/repository`, which is a failure, not a skip |
| `record_safety.sh` | run in the prune image: the recorder refuses a grading option, the layers as its command, the wrong image and a traced start, and nothing under `protecter/src/` names it | never |
| `record_interactive.sh` | run in the prune image on a pseudo-terminal: Ctrl+C, Ctrl+Z and fg reach the recorded program, its status is the recorder's, and a child that outlives it is still recorded | never |
| `record_replay.sh` | run in the prune image, one phase per container: the replay check passes in a fresh container with no regression, is refused in one that is not fresh (a leftover, a modified file, the recording's own) and fails on a policy that lacks a creation the session needed | never |
| `record_generate.sh` | run in the prune image, one phase per container: the generated policy is accepted by the parser, replays the recorded session with no regression, refuses what no session touched (canaries, a write into a read-only directory, an unrecorded connect and bind), merges a second session, fails the check of that session without it, and carries derived limits only where a batch session allows them | never |
| `record_networked.sh` | run on the host with the prune image and a Docker network that has no route out: a stand-in server answers DNS and TLS for `api.phobos.test`; the recorded HTTPS session becomes `allow api.phobos.test:443` with the note that the policy needs `--resolver`, the replay under the egress broker passes, and the server's address and the name on the plain port are refused | never |
| `record_host.sh` | run on the host: starts the record suites above, one container per phase, and checks that the run-phase image holds no strace and refuses the recorder | never |
| `kvm_fixture_result.sh` | run on the host by the manual `prune-kvm.yml`, after its guest, on the layer pruner's fixture with `FIXTURE_UDP=1`: the guest verified the policy on Landlock version 10 or later, compared a non-empty set of refusals strace attributed with the kernel's records without a mismatch, added exactly one row, `allow 5000 udp`, in a sidecar whose SHA-256 the record names, and the orchestrator writes it to `Abi10-java.cfg`, keeps it out of the base and refuses a sidecar changed afterwards | the guest could not boot or observe, which is a failure of the job, not a skip |
| `stage_prune_inputs.sh` | run on the host by `test.yml`: `.github/scripts/stage-prune-inputs.sh` stages a reference with the exercises the pruner's discovery assigns to the key, in the two-level tree, and the fixture under `java-gradle`; a tree the pruner would refuse ends it with a failure before an earlier staging is deleted | never |
| `runner-capability-probe.sh` | not a suite: it answers what a machine can do, and is run by `runner-capabilities.yml` on request, on each hosted runner image for the KVM question. It reports for itself rather than through the harness, because its statuses are its own | it is a diagnostic; the assert modes answer 0, 1 or 3. `--assert-kvm` needs QEMU and a readable kernel image, and `--assert-ptrace` needs gcc with a static libc and docker; each says indeterminate without them |

## Python suites, run by the `Python helpers` job of `test.yml`

The second job of the same workflow installs pytest and runs `python -m pytest pruner`.
It needs no container and no compiler: the artefacts are written as the layer pruner writes them,
and the runs are replaced by stand-ins, so these drive the helpers alone.

| Suite | What it proves | Skips when |
| --- | --- | --- |
| `exercise_pruner/test/unit/interface/test_orchestrate.py` | every way a language can drop out stops the merge rather than shrinking it: a language without artefacts or with an empty policy, an aborted exercise, a `.cfg` its record does not vouch for, a partial prune, a left-over path set; what the merge writes: the exact union, each exercise's own file, a union that would put execute beside a write refused. It drives the orchestrator as a subprocess, which is what keeps the entry point honest | never |
| `exercise_pruner/test/unit/interface/test_orchestrate_helpers.py` | the orchestrator's parts, which a subprocess test cannot reach on their own: that importing it does no work, the layout, the union and intersection across languages, what every exercise needed, and the execute conflicts | never |
| `shared/test/unit/domain/test_layer_prune_strace_parse.py` | how a `strace -f` log becomes the calls the layer pruner reasons about: an interrupted call is joined with its resumption, a thread belongs to its creator's group even where its clone is printed late, a process id handed out twice and a clone that returns the root's id are refused rather than guessed at, only processes after `landlock_restrict_self` are in the command's domain and the network layer's port-only domain does not put the filesystem layer in it, and every line of the recorded trace in `fixtures/strace/` parses | never |
| `shared/test/unit/domain/test_layer_prune_attribute.py` | how a refused call becomes the right that granting it needs, one case per kind of call (a read, a write, a truncation, a creation, a removal, a rename, an execution with its interpreter, a connect, a bind, a listen), and the filters that keep a refusal outside the domain, an ordinary error, another mechanism's refusal and a fixed rule of the guard from ever becoming a grant | never |
| `exercise_pruner/test/unit/infrastructure/test_layer_prune_control.py` | the control replay outside every Landlock domain: a refusal the uid meets anyway (a mode, a read-only file or directory, another filesystem's `EXDEV`, a port or a destination the kernel refuses) is never Landlock's, a readable or writable path is, and the replay truncates nothing, follows no link and leaves nothing behind | a case the machine cannot show: root, which no mode refuses, a port or an address the kernel does not refuse here, or a temporary directory on the same device as `/dev` |
| `runtime_pruner/test/unit/infrastructure/test_layer_record_guard.py` | the recorder's refusals, each beside the neighbour it accepts: a grading option, the run-phase image or a prune base beside another base, the layers started directly, through an interpreter or through `PATH`, and a recorder that is itself traced | never |
| `runtime_pruner/test/unit/infrastructure/test_layer_record_snapshot.py` | the listing of a container's starting state: every kind of path gets its fingerprint, a link is listed and not followed, names that could break a line round-trip, and what Docker creates per container does not tell two fresh containers apart | never |
| `runtime_pruner/test/unit/application/test_layer_record_check.py` | the replay check refuses the recording's own container without the opt-in, and calls another container fresh only where its starting state matches the recording's, so an added, a removed or a modified path is not fresh | never |
| `runtime_pruner/test/unit/infrastructure/test_layer_record_pty_script.py` | a scripted session typed through a real pseudo-terminal: the script is read line by line, an expectation that never holds fails the session, Ctrl+C reaches the program, the command's own status comes back, and a program that never ends is hung up on | never |
| `runtime_pruner/test/unit/domain/test_layer_record_names.py` | the host names recovered from a session, against the captured answers and ClientHellos in `fixtures/record/`: a DNS answer maps to the name asked through its alias chain and never to a name outside it, the TLS host name of a ClientHello is read, every truncation and every single corrupted byte is survived without an exception, and only a plain DNS name may become a rule | never |

## The prune image's observer, run by `build.yml` inside the prune image

`docker/pruner/layers/Dockerfile` builds the prune image on the run-phase image the same
job has just tested, adding `strace` and `python3` and replacing the base policy with
`BasePrune.cfg`, which grants nothing. The suite runs in an ordinary container with
`--network none`, `--memory` and `--pids-limit`, with `protecter/test/` and `pruner/` mounted
read-only.

| Suite | What it proves |
| --- | --- |
| `layer_prune_observer.sh` | the prune image ships `BasePrune.cfg` as its only base and `phobos-policysystem.sh` accepts it, `strace` records a Landlock refusal made inside the `phobos.sh` chain with its path and errno while a permitted read beside it succeeds, and the parser and attribution turn that record into exactly one filesystem denial and none for the permitted read |
## The Python run-phase image, run by the `run-phase-python` job of `build.yml`

The prune image is built on the Python run-phase image there and runs `layer_prune_observer.sh`,
`layer_prune.sh` and `layer_prune_egress.sh`, and prunes `exercises/python/python-reference`, which has
to end in a policy.

## The environment variables the suites read

| Variable | Read by | Meaning |
| --- | --- | --- |
| `PROBE_CONTAINER_IMAGE` | `runner-capability-probe.sh` | the image the container half of the probe runs in |
| `LAYER_PRUNE_HELPERS` | `layer_prune_observer.sh` | where the layer pruner's Python package is mounted; `/var/tmp/helpers` by default |
| `PRUNE_LOG_DIR`, `PRUNE_TARGET`, `TESTING_DIR`, `PHOBOS_KEEP_LOG` | the prune suites and the pruner itself | where a prune writes its logs, which tree it prunes, where the exercises live, and whether the raw log is kept |
