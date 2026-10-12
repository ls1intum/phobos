---
title: "Timeout"
sidebar_position: 4
description: "The layer that bounds a run in wall-clock time, and the contract for deciding that it did."
---

:::tip[Simple Story]
The layer that waits.

Three layers wait: this one, the network layer and the filesystem layer. This one stays outside
the process group, which is why it still tidies up after a group kill.
:::

## What it does

`phobos-timeoutsystem.sh` reads `timeout.sec` from the specification. Where it is empty, which
happens only where a configuration wrote `0`, the layer
hands the chain straight on with `exec` and applies no process-group lock, since there is no
group kill to escape. Where a timeout is set it runs the rest under GNU `timeout` and waits.

## What is in it

| File | Purpose |
| --- | --- |
| `phobos-timeoutsystem.sh` | the layer: the run, the wait, the timeout decision |
| `phobos-seccomp-timeoutsystem.c` | the seccomp filter refusing `setsid` and `setpgid` where no supervisor answers them, then `execvp` |
| `phobos-time.sh` | how a timeout is spelled, converted and compared |

## The contract for a timeout value

```
^[0-9]+(\.[0-9]{3})?$
```

Whole seconds, or seconds with exactly three decimal places. GNU `timeout` receives the value
with an explicit seconds suffix, so nothing converts units after this point.

`timeout_to_ms` and `ms_to_timeout` are the pair that makes two spellings of one value compare
as numbers and come back as one spelling, so `2` and `2.000` produce the same specification.
Both parts are read in base ten, never as octal, and the pattern guarantees a digit before the
point and exactly three after it, so neither field is ever empty.

## The contract for deciding a timeout happened

`run_reached_timeout` answers true only where both halves hold:

- the status is 124, which GNU `timeout` returns on expiry, or 137, which the `--kill-after`
  escalation produces;
- the elapsed wall clock is at least the timeout.

Neither alone is enough. A command can return 124 on its own, and the out-of-memory killer
produces the same 137 as the escalation.

The elapsed time comes from `EPOCHREALTIME`. `epoch_realtime_microseconds` drops every
character that is not a digit, because bash writes the decimal separator of the current locale,
and `EPOCHREALTIME` always carries exactly six decimals, so what is left is the microseconds.

## Why this layer tidies up

It is one of three layers that wait, and each has an `EXIT` trap that removes the specification
directory. The first to end does the work and the others find it gone. This layer sits outside
the group GNU `timeout` kills, so its trap still runs after the group kill has reached everything
below it. Where no timeout is set it hands over with `exec` and fires no trap, and the other two
remove the directory.

## Known gaps

**A clock stepped backwards during a run can hide a real expiry.** The elapsed time is wall
clock, so an expiry that looks too short passes the status through without the `PHB-ETIMEOUT`
label. The run itself is never extended by it.

**The kill escalation is a constant.** `PHB_KILL_AFTER_SECONDS` is five seconds and no
configuration reaches it. The filesystem layer's grace period for the denial counts is two
seconds and is kept below it deliberately.

## Further reading

- [timeout and the process-group lock](../technologies/timeout-and-the-process-group-lock.md)
- [phobos-timeoutsystem.sh](/user/protect-anything/phobos-timeout-sh): the same layer, from the
  outside
