"""Checks the [limits] margins of decision 3 and which limit a run's end is attributed to (A.6.5)."""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import limits, record


def measurement(wall: float, cpu: float, vm: float, tasks: int, fd: int, file: float) -> limits.Measurement:
    """One run's peaks."""
    return limits.Measurement(wall_seconds=wall, cpu_seconds=cpu, vm_peak_mb=vm, tasks=tasks,
                              highest_descriptor=fd, largest_file_mb=file)


def limit_denial(operation: str, errno: str) -> record.Denial:
    """A refusal by an exhausted resource, as attribute.denials builds it."""
    return record.Denial(pid=9, layer=record.LAYER_LIMIT, operation=operation, objects=(), sections=frozenset(),
                         address=None, port=None, transport=None, errno=errno)


def test_margins_take_the_maximum_over_runs_and_round_up():
    result = limits.margins([measurement(wall=41.0, cpu=30.2, vm=2100.0, tasks=70, fd=180, file=3.0),
                             measurement(wall=47.5, cpu=28.0, vm=2300.0, tasks=75, fd=150, file=2.0)],
                            limits.Margins(), heap_pinned=True)
    assert result == {"timeout": 240, "cpu": 160, "mem_mb": 4608, "nproc": 166, "nofile": 362, "fsize_mb": 16}


def test_a_small_run_gets_every_floor():
    result = limits.margins([measurement(wall=1.0, cpu=0.5, vm=100.0, tasks=3, fd=10, file=0.1)],
                            limits.Margins(), heap_pinned=True)
    assert result == {"timeout": 60, "cpu": 30, "mem_mb": 512, "nproc": 64, "nofile": 256, "fsize_mb": 16}


def test_an_exact_multiple_is_not_pushed_a_step_up_by_floating_point_noise():
    result = limits.margins([measurement(wall=30.0, cpu=0.1 * 3 * 100, vm=1.0, tasks=1, fd=1, file=1.0)],
                            limits.Margins(), heap_pinned=False)
    assert result["cpu"] == 150


def test_mem_mb_is_not_derived_without_a_pinned_heap():
    result = limits.margins([measurement(wall=41.0, cpu=30.2, vm=2100.0, tasks=70, fd=180, file=3.0)],
                            limits.Margins(), heap_pinned=False)
    assert "mem_mb" not in result


def test_limits_off_names_every_limit_with_zero():
    assert limits.LIMITS_OFF == {key: 0 for key in ("timeout", "cpu", "mem_mb", "nproc", "nofile", "fsize_mb")}


def test_status_fourteen_is_the_timeout():
    assert limits.limit_signature(14, [], {"timeout": 60}, [], []) == "timeout"


def test_sigxfsz_is_the_file_size_and_sigxcpu_the_cpu_time():
    assert limits.limit_signature(153, [], {"fsize_mb": 16}, [], []) == "fsize_mb"
    assert limits.limit_signature(152, [], {"cpu": 100}, [], []) == "cpu"


def test_sigkill_near_the_cpu_limit_is_the_cpu_limit():
    samples = [{"pid": 9, "cpu_seconds": 99.4}]
    assert limits.limit_signature(137, samples, {"cpu": 100}, [], []) == "cpu"


def test_sigkill_far_from_the_cpu_limit_is_not_a_phobos_limit():
    samples = [{"pid": 9, "cpu_seconds": 12.0}]
    assert limits.limit_signature(137, samples, {"cpu": 100}, [], []) is None


def test_enomem_counts_only_when_the_unlimited_run_did_not_also_see_it():
    seen_in_both = [limit_denial("mmap", "ENOMEM")]
    assert limits.limit_signature(1, [], {"mem_mb": 512}, seen_in_both, seen_in_both) is None
    assert limits.limit_signature(1, [], {"mem_mb": 512}, seen_in_both, []) == "mem_mb"


def test_an_exhausted_resource_counts_only_for_a_limit_the_run_had_and_on_its_own_calls():
    assert limits.limit_signature(1, [], {"nofile": 256}, [limit_denial("openat", "EMFILE")], []) == "nofile"
    assert limits.limit_signature(1, [], {"nproc": 64}, [limit_denial("clone3", "EAGAIN")], []) == "nproc"
    assert limits.limit_signature(1, [], {"nproc": 64}, [limit_denial("openat", "EMFILE")], []) is None
    assert limits.limit_signature(1, [], {"nofile": 256}, [limit_denial("read", "EMFILE")], []) is None


def test_a_limit_switched_off_is_never_the_signature():
    assert limits.limit_signature(1, [], {"nofile": 0}, [limit_denial("openat", "EMFILE")], []) is None
