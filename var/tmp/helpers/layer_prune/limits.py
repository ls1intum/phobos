"""[limits] from measured runs, with the margins of decision 3, and which limit ended a run (A.6.5).

Nothing here grants access. The measurements come from runs with every limit off under the final
filesystem and network policy; the margins put each limit well above them, and a limit is only raised
later when a run's end matches that limit's signature.
"""

from __future__ import annotations

import dataclasses
import math

from layer_prune import attribute
from layer_prune.record import LAYER_LIMIT, Denial

# [limits] with every limit switched off: zero means unbounded for each key (README, [limits]).
LIMITS_OFF = {"timeout": 0, "cpu": 0, "mem_mb": 0, "nproc": 0, "nofile": 0, "fsize_mb": 0}
# The statuses that name a limit on their own: the timeout layer's, SIGXFSZ (file size) and SIGXCPU
# (CPU time at the soft limit), each 128 plus the signal number for the signals.
TIMEOUT_STATUS = 14
SIGXFSZ_STATUS = 153
SIGXCPU_STATUS = 152
# SIGKILL's status, which is the CPU limit only when a process had nearly used it up.
SIGKILL_STATUS = 137
# How close to `cpu` the last sample of a process's CPU time must be for a SIGKILL to count as it.
CPU_KILL_WINDOW_SECONDS = 1.0
# The digits a measurement is rounded to before a margin is applied, so that floating-point noise in
# a product such as 30.2 x 5 cannot push a limit one rounding step up.
MEASUREMENT_DIGITS = 6
# The exhausted resource each limit shows as, checked in this order, on the calls attribution names
# for it (A.6.5).
ERRNO_SIGNATURES = (
    ("nofile", "EMFILE", attribute.LIMIT_CALLS["EMFILE"]),
    ("nproc", "EAGAIN", attribute.LIMIT_CALLS["EAGAIN"]),
    ("mem_mb", "ENOMEM", attribute.LIMIT_CALLS["ENOMEM"]),
)


@dataclasses.dataclass(frozen=True)
class Measurement:
    """What one run with every limit off used, at its peak: the quantities the six limits bound."""

    wall_seconds: float
    cpu_seconds: float
    vm_peak_mb: float
    tasks: int
    highest_descriptor: int
    largest_file_mb: float


@dataclasses.dataclass(frozen=True)
class Margins:
    """How far above the measurement each limit is put (decision 3), and the floor and rounding of each."""

    wall_factor: float = 5
    wall_floor: int = 60
    wall_step: int = 30
    cpu_factor: float = 5
    cpu_floor: int = 30
    cpu_step: int = 10
    memory_factor: float = 2
    memory_floor: int = 512
    memory_step: int = 256
    tasks_factor: int = 2
    tasks_extra: int = 16
    tasks_floor: int = 64
    descriptor_factor: int = 2
    descriptor_floor: int = 256
    file_factor: float = 2
    file_floor: int = 16
    file_step: int = 16


def ceil_to(value: float, step: int) -> int:
    """The smallest multiple of `step` at or above `value`, after rounding off floating-point noise."""
    return math.ceil(round(value / step, MEASUREMENT_DIGITS)) * step


def margins(measurements: list[Measurement], margins: Margins, heap_pinned: bool) -> dict[str, int]:
    """The [limits] values for an exercise: the maximum of each quantity over the runs, with its margin.

    `mem_mb` is derived only for an exercise that pins the heap of every JVM it starts (decision 4);
    otherwise it is left out, so the default of phobos-constants.sh applies.
    """
    wall = max(measurement.wall_seconds for measurement in measurements)
    cpu = max(measurement.cpu_seconds for measurement in measurements)
    memory = max(measurement.vm_peak_mb for measurement in measurements)
    tasks = max(measurement.tasks for measurement in measurements)
    descriptor = max(measurement.highest_descriptor for measurement in measurements)
    largest = max(measurement.largest_file_mb for measurement in measurements)
    result = {
        "timeout": max(margins.wall_floor, ceil_to(margins.wall_factor * wall, margins.wall_step)),
        "cpu": max(margins.cpu_floor, ceil_to(margins.cpu_factor * cpu, margins.cpu_step)),
        "nproc": max(margins.tasks_floor, margins.tasks_factor * tasks + margins.tasks_extra),
        "nofile": max(margins.descriptor_floor, margins.descriptor_factor * (descriptor + 1)),
        "fsize_mb": max(margins.file_floor, ceil_to(margins.file_factor * largest, margins.file_step)),
    }
    if heap_pinned:
        result["mem_mb"] = max(margins.memory_floor, ceil_to(margins.memory_factor * memory, margins.memory_step))
    return result


def near_the_cpu_limit(last_samples: list[dict], limits: dict[str, int]) -> bool:
    """Whether some process's last sampled CPU time was within CPU_KILL_WINDOW_SECONDS of `cpu`."""
    cpu = limits.get("cpu", 0)
    return cpu > 0 and any(sample.get("cpu_seconds", 0) >= cpu - CPU_KILL_WINDOW_SECONDS for sample in last_samples)


def errno_signatures(denials: list[Denial]) -> set[tuple[str, str]]:
    """The (call, errno) pairs of the limit refusals in a list of denials."""
    return {(denial.operation, denial.errno) for denial in denials if denial.layer == LAYER_LIMIT}


def limit_signature(status: int, last_samples: list[dict], limits: dict[str, int],
                    diagnosis: list[Denial], control: list[Denial]) -> str | None:
    """The limit that ended a run, or None where the run's end matches none (A.6.5).

    Status 14 is the timeout, 153 the file size, 152 and a SIGKILL near the CPU limit the CPU time;
    a SIGKILL far from it is the container's OOM killer, no Phobos limit. Otherwise an exhausted
    resource in the diagnostic observed run counts only when the run with the limits off did not show
    it too, since a JVM probes large reservations and falls back on its own; and only for a limit the
    run had switched on (a value above 0).
    """
    if status == TIMEOUT_STATUS:
        return "timeout"
    if status == SIGXFSZ_STATUS:
        return "fsize_mb"
    if status == SIGXCPU_STATUS or (status == SIGKILL_STATUS and near_the_cpu_limit(last_samples, limits)):
        return "cpu"
    if status == SIGKILL_STATUS:
        return None
    new = errno_signatures(diagnosis) - errno_signatures(control)
    for limit, errno, calls in ERRNO_SIGNATURES:
        if limits.get(limit, 0) > 0 and any(call in calls and seen == errno for call, seen in new):
            return limit
    return None
