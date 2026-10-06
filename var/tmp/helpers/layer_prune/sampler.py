"""Samples a run's process tree from /proc while it runs, for the limits stage (A.6.5).

Every interval the sampler walks the descendants of the run's first process and records, for each,
what the six limits bound per process: the peak address space (VmPeak, what `ulimit -v` bounds), the
CPU time (what `ulimit -t` bounds), the highest open descriptor (what `ulimit -n` bounds), and the
number of tasks of the whole tree, threads included. `ulimit -u` bounds every task of the uid instead;
in the prune container the run's tree is all the uid runs besides the pruner, and the tree also counts
Phobos's own helper processes, so the count errs high, towards a looser limit, never a tighter one.
The pruner makes itself a child subreaper first, so a daemon the build leaves behind is reparented to
it and stays a descendant that is sampled.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import pathlib
import threading
import time

# prctl's option that makes the caller the reaper of its orphaned descendants (linux/prctl.h).
PR_SET_CHILD_SUBREAPER = 36
# The default time between two samples, in seconds.
DEFAULT_INTERVAL_SECONDS = 0.1
# Kilobytes per megabyte, for VmPeak.
KILOBYTES_PER_MEGABYTE = 1024
# The fields of /proc/<pid>/stat after the command name that hold utime and stime, counted from the
# state field (field 3) as 0.
UTIME_FIELD = 11
STIME_FIELD = 12


def become_subreaper() -> bool:
    """Makes the calling process the child subreaper of its descendants; whether the kernel agreed."""
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0


def children_of(proc: pathlib.Path, pid: int) -> list[int]:
    """The direct children of a process, from the children file of each of its threads."""
    found: list[int] = []
    with contextlib.suppress(OSError):
        for task in (proc / str(pid) / "task").iterdir():
            with contextlib.suppress(OSError, ValueError):
                found.extend(int(child) for child in (task / "children").read_text().split())
    return found


def descendants(proc: pathlib.Path, root: int) -> list[int]:
    """The root process and every process below it, as far as /proc shows them right now."""
    seen: list[int] = []
    pending = [root]
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.append(pid)
        pending.extend(children_of(proc, pid))
    return seen


def vm_peak_mb(proc: pathlib.Path, pid: int) -> float:
    """The peak address space of a process in megabytes, 0 where /proc no longer shows it."""
    with contextlib.suppress(OSError, ValueError):
        for line in (proc / str(pid) / "status").read_text().splitlines():
            if line.startswith("VmPeak:"):
                return int(line.split()[1]) / KILOBYTES_PER_MEGABYTE
    return 0.0


def cpu_seconds(proc: pathlib.Path, pid: int, ticks: int) -> float:
    """The user and system CPU time a process has used, in seconds, 0 where /proc no longer shows it."""
    with contextlib.suppress(OSError, ValueError, IndexError):
        text = (proc / str(pid) / "stat").read_text()
        fields = text[text.rindex(")") + 2:].split()
        return (int(fields[UTIME_FIELD]) + int(fields[STIME_FIELD])) / ticks
    return 0.0


def highest_descriptor(proc: pathlib.Path, pid: int) -> int:
    """The highest descriptor number a process holds open, -1 where it holds none or is gone."""
    with contextlib.suppress(OSError, ValueError):
        return max((int(entry.name) for entry in (proc / str(pid) / "fd").iterdir()), default=-1)
    return -1


def task_count(proc: pathlib.Path, pid: int) -> int:
    """How many threads a process has, 0 where it is gone."""
    with contextlib.suppress(OSError):
        return sum(1 for _ in (proc / str(pid) / "task").iterdir())
    return 0


def sample_once(proc: pathlib.Path, root: int, ticks: int, moment: float, include_root: bool) -> list[dict]:
    """One sample of every process in the tree, each with the tree's task count at that moment."""
    pids = [pid for pid in descendants(proc, root) if include_root or pid != root]
    tasks = sum(task_count(proc, pid) for pid in pids)
    return [{"time": moment, "pid": pid, "vm_peak_mb": vm_peak_mb(proc, pid), "cpu_seconds": cpu_seconds(proc, pid, ticks),
             "highest_descriptor": highest_descriptor(proc, pid), "tasks": tasks} for pid in pids]


class Sampler:
    """Samples the tree below `root_pid` every `interval` seconds on a thread of its own, until stopped.

    The runner passes its own process with include_root false: as the child subreaper it is where a
    daemon the build leaves behind ends up, so its tree, without itself, is everything the run started.
    """

    def __init__(self, root_pid: int, interval: float = DEFAULT_INTERVAL_SECONDS, proc: str = "/proc",
                 include_root: bool = True) -> None:
        """Prepares the sampler; nothing is read until start."""
        self.root_pid = root_pid
        self.include_root = include_root
        self.interval = interval
        self.proc = pathlib.Path(proc)
        self.ticks = os.sysconf("SC_CLK_TCK")
        self.samples: list[dict] = []
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def loop(self) -> None:
        """Takes a sample, waits an interval, and repeats until stop is asked for."""
        started = time.monotonic()
        while not self.stopping.is_set():
            self.samples.extend(sample_once(self.proc, self.root_pid, self.ticks, time.monotonic() - started,
                                            self.include_root))
            self.stopping.wait(self.interval)

    def start(self) -> None:
        """Starts sampling."""
        self.thread.start()

    def stop(self) -> list[dict]:
        """Stops sampling and returns every sample taken."""
        self.stopping.set()
        self.thread.join()
        return list(self.samples)
