"""Checks the sampler against a /proc tree built in a temporary directory, and its measurement of a run."""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import sampler

TICKS = 100


def process(proc: pathlib.Path, pid: int, children: list[int], vm_peak_kb: int, utime: int, stime: int,
            descriptors: list[int], threads: int = 1) -> None:
    """Writes one process's status, stat, fd and task entries into a fake /proc."""
    root = proc / str(pid)
    (root / "fd").mkdir(parents=True)
    for descriptor in descriptors:
        (root / "fd" / str(descriptor)).write_text("")
    for number in range(threads):
        task = root / "task" / str(pid + number)
        task.mkdir(parents=True)
        (task / "children").write_text(" ".join(map(str, children)) if number == 0 else "")
    (root / "status").write_text(f"Name:\tx\nVmPeak:\t{vm_peak_kb} kB\nUid:\t0\t0\t0\t0\n")
    fields = ["S"] + ["0"] * 10 + [str(utime), str(stime)] + ["0"] * 10
    (root / "stat").write_text(f"{pid} (a name with ) in it) " + " ".join(fields) + "\n")


def test_one_sample_walks_the_tree_and_reads_every_quantity(tmp_path):
    process(tmp_path, 10, [11, 12], vm_peak_kb=2048, utime=150, stime=50, descriptors=[0, 1, 2], threads=2)
    process(tmp_path, 11, [], vm_peak_kb=4096, utime=10, stime=0, descriptors=[0, 7])
    process(tmp_path, 12, [13], vm_peak_kb=1024, utime=0, stime=0, descriptors=[])
    process(tmp_path, 13, [], vm_peak_kb=512, utime=0, stime=5, descriptors=[3])
    samples = {sample["pid"]: sample for sample in sampler.sample_once(tmp_path, 10, TICKS, 0.0, True)}
    assert set(samples) == {10, 11, 12, 13}
    assert samples[10]["vm_peak_mb"] == 2.0
    assert samples[10]["cpu_seconds"] == 2.0
    assert samples[11]["highest_descriptor"] == 7
    assert samples[12]["highest_descriptor"] == -1
    assert samples[10]["tasks"] == 5


def test_the_root_can_be_left_out_and_a_vanished_process_reads_as_zero(tmp_path):
    process(tmp_path, 10, [11, 99], vm_peak_kb=2048, utime=0, stime=0, descriptors=[])
    process(tmp_path, 11, [], vm_peak_kb=4096, utime=0, stime=0, descriptors=[])
    samples = {sample["pid"]: sample for sample in sampler.sample_once(tmp_path, 10, TICKS, 0.0, False)}
    assert set(samples) == {11, 99}
    assert samples[99]["vm_peak_mb"] == 0.0
    assert samples[99]["cpu_seconds"] == 0.0


def test_a_sampler_started_and_stopped_returns_its_samples(tmp_path):
    process(tmp_path, 10, [], vm_peak_kb=1024, utime=0, stime=0, descriptors=[])
    watcher = sampler.Sampler(10, interval=0.01, proc=str(tmp_path))
    watcher.start()
    samples = watcher.stop()
    assert samples
    assert all(sample["pid"] == 10 for sample in samples)


def test_a_process_named_in_exclude_is_left_out_of_the_samples_and_of_the_task_count(tmp_path):
    process(tmp_path, 10, [11, 12], vm_peak_kb=2048, utime=0, stime=0, descriptors=[])
    process(tmp_path, 11, [], vm_peak_kb=4096, utime=900, stime=0, descriptors=[], threads=2)
    process(tmp_path, 12, [], vm_peak_kb=1024, utime=0, stime=0, descriptors=[])
    (tmp_path / "10" / "comm").write_text("tool\n")
    (tmp_path / "11" / "comm").write_text("strace\n")
    (tmp_path / "12" / "comm").write_text("tool\n")
    samples = sampler.sample_once(tmp_path, 10, TICKS, 0.0, True, frozenset({"strace"}))
    assert {sample["pid"] for sample in samples} == {10, 12}
    assert {sample["tasks"] for sample in samples} == {2}
