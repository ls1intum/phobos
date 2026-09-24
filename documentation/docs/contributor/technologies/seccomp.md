---
title: "Seccomp"
sidebar_position: 2
description: "The syscall filter behind the connect guard and the process-group lock, and the two ways Phobos uses it."
---

:::tip[Simple Story]
A filter sits between the program and the kernel and reads every request before the kernel
does.

It can answer a request itself, and it can pass the request to somebody outside who answers on
the program's behalf. Phobos uses both, for two different jobs.
:::

## What it is

Seccomp filters system calls. A process installs a classic Berkeley Packet Filter program that
the kernel runs on every call, over a small structure holding the call number, its arguments
and the architecture it came from. The filter returns an action: allow the call, fail it with
an error number, kill the process, or notify a supervising process and wait for its answer.

Installing one needs no privilege, provided `PR_SET_NO_NEW_PRIVS` is set first. A filter is
inherited across `fork` and survives `execve`, which is what lets Phobos install one high in
the chain and have it hold all the way down to the command.

## Use one: the process-group lock

`phobos-pgroup-lock` installs the smallest filter in the repository and then becomes the rest
of the chain:

```
if arch != <native>            -> EACCES
if syscall is setsid           -> EACCES
if syscall is setpgid          -> EACCES
otherwise                      -> allow
```

The first line matters as much as the other two. Syscall numbers differ between one
application binary interface (ABI) and another, so a `setsid` made through an alternate one, the 32-bit entry on
x86-64 or x32, would slip past a comparison written against the native numbers. Refusing every
non-native ABI outright closes that.

The refusal is `EACCES`, the answer an ordinary denied call gives, rather than a kill: the
command sees a permission error and can report it.

Why those two calls: the timeout layer bounds a run by signalling a whole process group, and a
process that starts a new session or group leaves that group. Without the lock, a timed command
could outlive its limit through a detached child.

## Use two: the connect guard

The connect guard uses the other action, `SECCOMP_RET_USER_NOTIF`. Its filter traps a call to a
notification file descriptor, and a supervisor outside the sandbox reads the notification,
decides, and answers.

The guard forks before it installs anything. The child installs the filter, passes the
notification descriptor up to the parent over a UNIX socket pair, and execs the rest of the
chain. The parent becomes the supervisor and is never restricted.

What the filter traps or refuses:

| Call | Action | Why |
| --- | --- | --- |
| `connect` | notify | the decision the guard exists to make |
| `sendto`, `sendmsg`, `sendmmsg` | notify | a datagram carries its own destination, and TCP Fast Open can open a connection past a `connect` |
| `socket` | notify | a raw, packet or ICMP socket is refused before it exists |
| `io_uring_setup` and its siblings | refuse | a second syscall interface that would reach `connect` unseen |
| `setsid`, `setpgid` | refuse | the same escape the process-group lock closes |

**The supervisor connects on the command's behalf rather than letting the call continue.**
Seccomp offers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, which re-runs the original call, and that
would re-read the destination from the command's memory at a later moment: a command could show
one address to the check and connect to another once it passed. Making the connection in the
supervisor, from the address the check read, closes that window. The connected socket is handed
back with `SECCOMP_IOCTL_NOTIF_ADDFD`.

A datagram `connect` is different: it only sets a default peer, which cannot be injected the
same way, so it is checked and then allowed through. The boundary for a datagram is the checked
send that follows.

Reading the destination out of the child's memory uses `process_vm_readv`, which a parent may
do to its own child in an ordinary container. No capability, no container flag.

## Where seccomp sits relative to Landlock

Seccomp intercepts a call at the syscall boundary, before the kernel path where Landlock would
check a port. The supervisor therefore connects **outside** Landlock, which is why the guard is
the whole connect boundary where it runs, host and port together, and why the Landlock port
rules remain a second, kernel-enforced expression of the same ports rather than the only one.

## Both filters stack

The connect guard refuses `setsid` and `setpgid` for the command it supervises, and so does the
process-group lock. That is not duplication to remove: the guard's cover belongs to the network
layer, and the lock's belongs to the timeout layer, so a run with the network restriction
disabled keeps the group kill unescapable. Where both filters speak, the kernel takes the
stricter action, and denying one call twice denies it once.

## Further reading

- [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html) — the system call and its
  return actions
- [`seccomp_unotify(2)`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) — the
  user-notification mechanism, including the caveats around `CONTINUE`
- [Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html) — the kernel
  documentation
- [`process_vm_readv(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
- [`setsid(2)`](https://man7.org/linux/man-pages/man2/setsid.2.html) and
  [`setpgid(2)`](https://man7.org/linux/man-pages/man2/setpgid.2.html)
