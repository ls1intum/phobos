# The protection matrix

These suites check, through `phobos.sh` and nothing else, that what Phobos promises is what a
sandboxed command meets. Each promise is a denial that must hold, a permitted neighbour that must
still work, and a layer that is named as the reason. The claim they support is narrow and exact:
the protections the documentation promises are exercised in both directions in an ordinary container,
wherever this kernel and the container allow it, and the limits the documentation admits are pinned so
they cannot change unnoticed. What could not be exercised is listed at the end. It is not a proof that no
other bypass exists.

## Running them

They run inside the run-phase image, in an ordinary container: no `--privileged`, no `--cap-add`,
no `--security-opt`, and `--network none`. Memory and process caps are cgroup limits, not
privileges, and the resource suite wants them so that a runaway fork cannot reach the host.

```
docker run --rm --network none --memory 3g --pids-limit 1024 -v "${PWD}/tests:/tests:ro" \
  phobos-run-phase:ci bash /tests/integration/protection-matrix/run-all.sh
```

Run them in a disposable container, as above: the suites replace the image's base policy for their
duration and end helper processes with `pkill`, which is right in a container made for the run and
wrong in a shared one. Name suites to run only those: `run-all.sh network timeout`. Each suite compiles `probe.c` itself
with the image's `gcc-14`, installs a minimal base policy for its duration and restores the image's
own on exit, so no suite depends on another and none leaves the image changed.

## How a check is built

- **Three partners for every denial.** The operation must succeed with no sandbox (the control),
  must fail with `EACCES` or `EPERM` through `phobos.sh`, and must succeed again with only the layer
  under test switched off. A control that fails is a skip that says "no evidence", never a pass. A
  denial that survives switching its layer off was not that layer's doing, and fails.
- **A permitted neighbour beside every denial**, so a sandbox that denies everything cannot pass.
- **The probe says what happened.** `probe.c` prints `START` once the command runs, then one
  `OP <name> ret=<n> errno=<NAME>` line per operation. A run that never printed `START` was refused
  before the command, which is told apart from a command that was denied.
- **Gaps are asserted as they are** (`gap_case`). A limit the documentation admits is checked to hold
  today, so a change in either direction turns the suite red until the check and the documentation
  agree.
- **Known defects are skipped while they hold** (`known_defect`) and fail the moment they stop
  holding, so whoever fixes one turns the check into an ordinary one. A skip is one of two things,
  and the output says which: a known defect, or a control that could not run (the container's own
  seccomp profile blocks `mount`, user namespaces and `io_uring`, so there is no evidence either way).
  A skip is never a pass.
- **Everything has a watchdog.** A run that hangs is ended from outside, and probe loops are capped.

## The suites

| Suite | What it covers |
| --- | --- |
| `filesystem.sh` | the filesystem layer one right at a time (read, write, create, delete, refer, execute, ipc, symbolic links), what each right does not grant, children inheriting the ruleset, the dynamic loader and `LD_PRELOAD`, escape attempts (mount, chroot, user namespaces, widening a ruleset, no-new-privs being set, ptrace, signals, abstract sockets), and the documented gaps |
| `network.sh` | TCP connect by address, range, name, port and family, a bare run, UDP send and connect with receivers that count datagrams, the destination race for four send calls, inherited sockets, `bind` and `listen` closed unless a `[bind]` row opens them, the listen race, `[accept]` source filtering, and names (no resolver, wildcards, the egress broker end to end with a decoy) |
| `timeout.sh` | a run ended at its limit with the timeout status, children and descendants ended with it, `setsid` and `setpgid` refused by both guards, an orphaned descendant, a caller reading through a pipe released at the limit, merging, zero, milliseconds, defaults, invalid values, and exit statuses passing through |
| `resources.sh` | every limit set and read back from the kernel, enforced on a bounded behaviour, inherited, merged, defaulted, validated, and the helpers around the command not held to them |
| `combinations.sh` | all sixteen subsets of switched-off layers, one witness per layer in one run each, `--no-restriction` against all four switches, flag spellings, order and repetition, concurrent runs, and a nested `phobos.sh` that cannot widen its outer sandbox |
| `cli.sh` | the manual and usage errors, arguments that arrive unchanged, standard streams, the denial report, commands that cannot start, the environment, the override options, tail flags, the base policy, odd policy files, and the specification directory kept out of the command's reach |
| `lifecycle.sh` | nothing left behind after every way a run can end, the hosts file restored, the hosts lock bounded, and what a signal sent to `phobos.sh` does |

## What each of the eleven promises is checked by

| Promise | Checked in |
| --- | --- |
| read files | `filesystem.sh` |
| write files | `filesystem.sh` |
| execute files | `filesystem.sh` |
| create files | `filesystem.sh` |
| delete files | `filesystem.sh` |
| connect over TCP | `network.sh` |
| connect over UDP | `network.sh` (on a kernel with Landlock version 10 the port rules as well; on version 8 the guard alone, which is what that kernel can offer) |
| offer a TCP service | `network.sh` (`[bind]`, `[accept]`) |
| offer a UDP service | `network.sh` (needs Landlock version 10 to be closed, and says so below it; the permitted-port cases run only on a kernel that has it) |
| end after a time | `timeout.sh` |
| bound resources | `resources.sh` |

The combinations, the command line and the lifecycle cut across all eleven and are in the last three
suites.

## Defects the suites found

None of these lets a command reach something it was not granted. Each is a `known_defect`, so the
suite is green while it holds and red when it is fixed. They are ordinary bugs, not vulnerabilities,
in the sense of `SECURITY.md`.

1. **Moving a file between directories fails under the default layers.** With the network layer on,
   a rename or hard link across two directories fails with `EXDEV` even where `[restructure]` grants
   it, and works with `-nnr`. The network layer's own Landlock ruleset handles no reparenting right,
   and Landlock refuses every reparenting that a stacked ruleset does not handle. Making that ruleset
   handle the right and grant it on `/` would not widen the filesystem ruleset beside it, but that
   needs measuring before it is trusted. Found in `filesystem.sh`.
2. **A space inside a limit value was dropped.** Fixed: `cpu=5 5` is now refused like every other malformed value.
3. **A signal sent to `phobos.sh` never reaches the command.** `SIGTERM` with the timeout layer on,
   and `SIGHUP` either way, end the wrapper and remove the specification directory but leave the
   command running until its own limit. `SIGTERM` with no timeout layer is not acted on at all while
   the command runs, because the shell that waits for it defers the signal. The layers need to pass the
   signal on to the command. Found in `lifecycle.sh`.
An orphaned descendant that outlives a command which has already exited was suspected to be a fifth
and is not one: the run waits for the process group and ends it at the limit. `timeout.sh` pins that.

## Limits asserted as they are

These are the `gap_case` checks. The first group is documented in `SECURITY.md` or the user
documentation, and the suite checks the documentation still tells the truth.

- a descriptor opened before the sandbox keeps working, for a file and for a connected stream or
  datagram socket (an address-less send, never one that names a destination)
- a program in a tree with only the read right runs through the dynamic loader, and a copy in an
  anonymous memory file runs
- the existence and metadata of a path outside every tree stay visible, and `chmod`, `utime` and
  `setxattr` work on a file with only the read right
- below Landlock version 10 a UDP port can be bound with no `[bind]` row, and the enforcer says so
- the address space limit is per process, not per run
- `sendmsg` on a connected TCP socket is refused by the guard, the stated price of closing the datagram
  race, so programs that send that way break under a `[connect]` rule

The second group is behaviour nothing documents, found while writing the suites, and pinned as it is.

1. **A tail flags file that does not exist is ignored**, so a minimum Landlock version in the real
   file would be lost without a word. The tail flags are operator-trusted input.
2. **A relative path in a policy is resolved against the directory `phobos.sh` runs in.**
3. **The denial report counts text.** A line the command prints on standard error that happens to
   contain the words is counted, and the report is a hint, not a measure.
4. **A nested `phobos.sh` with its network layer on is refused**, because one process tree can have only
   one connect guard. With `-nnr` it starts and cannot widen what the outer policy hid.
5. **`chroot` works** for a process that holds `CAP_SYS_CHROOT`, root in a container by default. Landlock
   does not restrict it, and the directory chosen is still subject to the ruleset.

## What these suites do not cover

- Landlock versions above the kernel's. The reference environment, Docker Desktop, offers version 8,
  so the UDP port rules and everything gated on version 9 or 10 are skipped or asserted as the older
  behaviour. A kernel with version 10 needs the same suites run once more there.
- A successful UDP host-name resolution, its address snapshot and the guard's refusals of received or evicted
  descriptors, oversize datagrams and UNIX-addressed sends. They need Landlock version 10 or reach into the
  guard's internals, and `seccomp_networksystem.sh` and the unit suites under `tests/unit/` cover them.
- Other architectures than the one the suites ran on. CI runs the image on amd64 and arm64.
- The shipped Java policy. The suites install a minimal base so that every grant in a case is theirs,
  and `shipped-policy-test.sh` in the acceptance folder covers the real one.
- Hosts that are not an ordinary container. `--network none` is the container's job, not Phobos's.
- A fault the suites did not think to try. Each promise is exercised in both directions, which
  supports saying it works, not saying it cannot fail.
