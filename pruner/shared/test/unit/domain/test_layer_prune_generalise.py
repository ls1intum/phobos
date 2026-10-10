"""Checks how filesystem denials become grants, and in which direction each rule errs (A.6.5, A.7)."""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from shared.src.domain import generalise, record

FINE = generalise.DEFAULT_FINE_ROOTS


def denial(path: str, section: str, run: int = 1, pid: int = 300, tid: int | None = None,
           operation: str = "openat") -> record.Denial:
    """A filesystem denial of one section on one path."""
    return record.Denial(pid=pid, layer=record.LAYER_FILESYSTEM, operation=operation, objects=(path,),
                         sections=frozenset({section}), address=None, port=None, transport=None, errno="EACCES",
                         run=run, tid=pid if tid is None else tid)


def read(path: str, **keywords) -> record.Denial:
    """A refused read of one path."""
    return denial(path, "read", **keywords)


def create(path: str) -> record.Denial:
    """A refused creation in one directory."""
    return denial(path, "create", operation="mkdirat")


def snapshot_with(*paths: str, directories: tuple[str, ...] = ()) -> generalise.Snapshot:
    """A hermetic snapshot: the whole tree was scanned and holds exactly these paths and directories."""
    return generalise.Snapshot(existing=frozenset(paths) | frozenset(directories),
                               directories=frozenset(directories), scanned=("/",))


def test_a_read_outside_fine_roots_is_granted_on_the_directory_permissively():
    grants = generalise.grants_for([read("/usr/lib/jvm/lib/modules")],
                                   snapshot_with("/usr/lib/jvm/lib/modules", directories=("/usr/lib/jvm/lib",)), FINE)
    assert grants == {"/usr/lib/jvm/lib": frozenset({"read"})}


def test_a_read_under_etc_is_granted_on_the_file_only():
    grants = generalise.grants_for([read("/etc/hosts")], snapshot_with("/etc/hosts", directories=("/etc",)), FINE)
    assert grants == {"/etc/hosts": frozenset({"read"})}


def test_a_read_of_a_directory_is_granted_on_the_directory_itself():
    grants = generalise.grants_for([read("/usr/share/doc")], snapshot_with(directories=("/usr/share/doc",)), FINE)
    assert grants == {"/usr/share/doc": frozenset({"read"})}


def test_a_read_of_a_top_level_file_is_never_widened_to_the_root():
    grants = generalise.grants_for([read("/opt/tool.jar")], snapshot_with("/opt/tool.jar", directories=("/opt",)),
                                   ("/x",))
    assert grants == {"/opt/tool.jar": frozenset({"read"})}


def test_a_file_the_run_created_is_granted_on_the_nearest_pre_existing_ancestor():
    grants = generalise.grants_for([create("/w/build/tmp/x123")], snapshot_with(directories=("/w", "/w/build")), FINE)
    assert grants == {"/w/build": frozenset({"create"})}


def test_a_write_on_an_existing_file_stays_on_that_file():
    grants = generalise.grants_for([denial("/usr/lib/out.log", "write")],
                                   snapshot_with("/usr/lib/out.log", directories=("/usr/lib",)), FINE)
    assert grants == {"/usr/lib/out.log": frozenset({"write"})}


def test_compaction_never_reaches_the_root_or_a_top_level_write():
    grants = {"/usr/a": frozenset({"write"}), "/usr/b": frozenset({"write"}), "/usr/c": frozenset({"write"})}
    assert generalise.compact(grants, 3, FINE) == grants


def test_compaction_never_joins_into_a_top_level_directory():
    grants = {"/usr/a": frozenset({"read"}), "/usr/b": frozenset({"read"}), "/usr/c": frozenset({"read"})}
    assert generalise.compact(grants, 3, FINE) == grants


def test_compaction_never_happens_inside_a_fine_grained_root():
    grants = {"/etc/a": frozenset({"read"}), "/etc/b": frozenset({"read"}), "/etc/c": frozenset({"read"}),
              "/root/.m2/repository/x/1/x.jar": frozenset({"read"}),
              "/root/.m2/repository/x/1/x.pom": frozenset({"read"}),
              "/root/.m2/repository/x/1/x.jar.sha1": frozenset({"read"})}
    assert generalise.compact(grants, 3, FINE) == grants


def test_three_siblings_with_equal_read_rights_compact_into_their_parent():
    grants = {"/usr/lib/a": frozenset({"read"}), "/usr/lib/b": frozenset({"read"}), "/usr/lib/c": frozenset({"read"})}
    assert generalise.compact(grants, 3, FINE) == {"/usr/lib": frozenset({"read"})}


def test_two_siblings_or_unequal_rights_are_not_compacted():
    two = {"/usr/lib/a": frozenset({"read"}), "/usr/lib/b": frozenset({"read"})}
    mixed = {"/usr/lib/a": frozenset({"read"}), "/usr/lib/b": frozenset({"read"}),
             "/usr/lib/c": frozenset({"read", "execute"})}
    assert generalise.compact(two, 3, FINE) == two
    assert generalise.compact(mixed, 3, FINE) == mixed


def test_a_process_id_seen_changing_is_granted_on_proc_with_its_reason():
    grants, comments = generalise.per_run_grants([read("/proc/412/status", run=1, pid=300),
                                                  read("/proc/977/status", run=2, pid=301)])
    assert grants == {"/proc": frozenset({"read"})}
    assert comments["/proc"].startswith("per-run name: /proc/<pid>/status")
    assert "observed as /proc/412/status and /proc/977/status" in comments["/proc"]


def test_the_callers_own_process_id_is_a_per_run_name_from_one_run():
    grants, _ = generalise.per_run_grants([read("/proc/412/stat", run=1, pid=412)])
    assert grants == {"/proc": frozenset({"read"})}


def test_the_callers_own_thread_id_is_a_per_run_name_in_its_task_directory():
    grants, _ = generalise.per_run_grants([read("/proc/1/task/415/stat", run=1, pid=412, tid=415)])
    assert grants == {"/proc/1/task": frozenset({"read"})}


def test_another_processes_id_seen_once_is_granted_file_by_file_elsewhere():
    denials = [read("/proc/1/cmdline", run=1, pid=300)]
    grants, _ = generalise.per_run_grants(denials)
    assert grants == {}
    assert generalise.grants_for(denials, snapshot_with("/proc/1/cmdline", directories=("/proc/1",)), FINE) == {
        "/proc/1/cmdline": frozenset({"read"})}


def test_the_same_value_in_two_runs_is_not_seen_changing():
    grants, _ = generalise.per_run_grants([read("/proc/1/cmdline", run=1), read("/proc/1/cmdline", run=2)])
    assert grants == {}


def test_a_pseudo_terminal_number_seen_changing_is_granted_on_dev_pts_for_reading_only():
    denials = [denial("/dev/pts/3", "read", run=1), denial("/dev/pts/7", "read", run=2)]
    grants, _ = generalise.per_run_grants(denials)
    assert grants == {"/dev/pts": frozenset({"read"})}


def test_a_write_class_right_on_a_per_run_name_is_never_widened_and_is_reported():
    denials = [denial("/dev/pts/3", "write", run=1), denial("/dev/pts/7", "write", run=2),
               denial("/proc/412/oom_score_adj", "write", run=1, pid=412)]
    grants, _ = generalise.per_run_grants(denials)
    assert grants == {}
    found, notes = generalise.grants_and_notes(denials, snapshot_with("/dev/pts/3", "/dev/pts/7"), FINE)
    assert found == {}
    assert len(notes.reported) == 3


def test_a_changing_name_outside_the_table_is_never_generalised():
    grants, _ = generalise.per_run_grants([read("/run/lock/a8f3", run=1, pid=300), read("/run/lock/c91d", run=2, pid=301)])
    assert grants == {}


def test_grants_for_leaves_a_per_run_name_to_per_run_grants():
    denials = [read("/proc/412/status", run=1, pid=412)]
    assert generalise.grants_for(denials, snapshot_with("/proc/412/status"), FINE) == {}


def test_proc_self_is_rewritten_with_the_thread_group_never_the_thread_or_the_pruner():
    assert generalise.rewrite_self("/proc/self/status", tgid=412, tid=415) == "/proc/412/status"
    assert generalise.rewrite_self("/proc/thread-self/stat", tgid=412, tid=415) == "/proc/412/task/415/stat"
    assert generalise.rewrite_self("/proc/self/status", tgid=412, tid=415) != f"/proc/{os.getpid()}/status"
    assert generalise.rewrite_self("/proc/selfish", tgid=412, tid=415) == "/proc/selfish"


def test_a_strict_subset_under_a_wider_ancestor_is_raised_not_dropped():
    grants = {"/usr": frozenset({"read", "execute"}), "/usr/bin": frozenset({"read"})}
    assert generalise.normalise_hierarchy(grants) == {"/usr": frozenset({"read", "execute"}),
                                                      "/usr/bin": frozenset({"read", "execute"})}


def test_different_rights_on_a_nested_entry_are_left_alone():
    grants = {"/usr": frozenset({"read", "execute"}), "/usr/out": frozenset({"write"})}
    assert generalise.normalise_hierarchy(grants) == grants


def test_a_path_with_a_wildcard_character_is_generalised_to_its_parent_and_reported():
    grants, notes = generalise.grants_and_notes(
        [read("/srv/data/a[1]/f")], snapshot_with("/srv/data/a[1]/f", directories=("/srv/data", "/srv/data/a[1]")), FINE)
    assert grants == {"/srv/data": frozenset({"read"})}
    assert "widened to /srv/data" in notes.reported[0]["reason"]


@pytest.mark.parametrize(("path", "sections"), [("/srv/x[1]/f", ("read", "write")), ("/etc/a#b", ("read", "write")),
                                               ("/usr/lib/a\x1bb", ("write",))])
def test_a_name_no_policy_line_can_carry_is_never_widened_to_a_shallow_directory_or_a_write(path, sections):
    for section in sections:
        grants, notes = generalise.grants_and_notes([denial(path, section)], snapshot_with(path), FINE)
        assert grants == {}
        assert notes.reported


def test_a_missing_path_outside_the_scanned_roots_is_reported_never_climbed_from():
    snapshot = generalise.Snapshot(existing=frozenset({"/w"}), directories=frozenset({"/w"}), scanned=("/w",))
    for section in ("read", "write", "create"):
        grants, notes = generalise.grants_and_notes([denial("/proc/999999/stat", section, pid=1)], snapshot, FINE)
        assert grants == {}
        assert notes.reported


def test_a_climb_never_reaches_a_shallow_directory():
    snapshot = generalise.Snapshot(existing=frozenset({"/w"}), directories=frozenset({"/w"}), scanned=("/w",))
    grants, notes = generalise.grants_and_notes([create("/w/build/x")], snapshot, FINE)
    assert grants == {}
    assert notes.reported


def test_values_seen_in_every_run_are_stable_however_many_there_are():
    denials = [read("/proc/1/stat", run=1), read("/proc/50/stat", run=1), read("/proc/1/stat", run=2),
               read("/proc/50/stat", run=2)]
    grants, _ = generalise.per_run_grants(denials)
    assert grants == {}


def test_a_value_one_run_lacks_is_changing_and_a_value_every_run_has_is_not():
    denials = [read("/proc/1/stat", run=1), read("/proc/412/stat", run=1), read("/proc/1/stat", run=2),
               read("/proc/977/stat", run=2)]
    taken = generalise.classify_per_run(denials)
    assert {path for _, path in taken} == {"/proc/412/stat", "/proc/977/stat"}


def test_a_directory_object_is_granted_on_itself_only_deep_enough_and_with_a_comment_in_a_fine_root():
    shallow, notes = generalise.grants_and_notes([read("/opt")], snapshot_with(directories=("/opt",)), FINE)
    assert shallow == {}
    assert notes.reported
    deep, notes = generalise.grants_and_notes([read("/etc/ssl/certs")], snapshot_with(directories=("/etc/ssl/certs",)), FINE)
    assert deep == {"/etc/ssl/certs": frozenset({"read"})}
    assert notes.comments["/etc/ssl/certs"].startswith("listed:")


def test_proc_self_is_rewritten_before_it_is_granted_and_reported_without_ids():
    grants = generalise.grants_for([read("/proc/self/status", pid=412, tid=415)], snapshot_with(), FINE)
    assert grants == {}
    assert generalise.per_run_grants([read("/proc/self/status", pid=412, tid=415)])[0] == {"/proc": frozenset({"read"})}
    unnamed = record.Denial(pid=0, layer=record.LAYER_FILESYSTEM, operation="openat", objects=("/proc/self/status",),
                            sections=frozenset({"read"}), address=None, port=None, transport=None, errno="EACCES")
    grants, notes = generalise.grants_and_notes([unnamed], snapshot_with(), FINE)
    assert grants == {}
    assert notes.reported


def test_a_compaction_threshold_below_two_is_refused():
    with pytest.raises(ValueError):
        generalise.compact({}, 1, FINE)


def test_compaction_cascades_and_normalisation_reaches_every_level():
    grants = {f"/usr/lib/{parent}/{child}": frozenset({"read"}) for parent in "abc" for child in "xyz"}
    assert generalise.compact(grants, 3, FINE) == {"/usr/lib": frozenset({"read"})}
    nested = {"/usr": frozenset({"read", "execute"}), "/usr/lib": frozenset({"read"}), "/usr/lib/jvm": frozenset({"read"})}
    assert all(sections == frozenset({"read", "execute"}) for sections in generalise.normalise_hierarchy(nested).values())


def test_a_snapshot_resolves_its_roots_and_refuses_an_unreadable_directory(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    snapshot = generalise.Snapshot.take([str(tmp_path / "link")])
    assert snapshot.scanned == (str((tmp_path / "real").resolve()),)
    locked = tmp_path / "real" / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        if os.geteuid() != 0:
            with pytest.raises(OSError):
                generalise.Snapshot.take([str(tmp_path / "real")])
    finally:
        locked.chmod(0o755)


def test_other_layers_are_ignored():
    network = record.Denial(pid=1, layer=record.LAYER_NETWORK, operation="connect", objects=(),
                            sections=frozenset({"connect"}), address="10.0.0.1", port=80, transport="tcp",
                            errno="EACCES")
    assert generalise.grants_for([network], snapshot_with(), FINE) == {}


def test_a_snapshot_taken_from_disk_tells_files_the_run_created_from_files_that_were_there(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "kept.txt").write_text("x")
    snapshot = generalise.Snapshot.take([str(tmp_path)])
    (tmp_path / "build" / "new.txt").write_text("y")
    assert snapshot.existed(str(tmp_path / "build" / "kept.txt"))
    assert not snapshot.existed(str(tmp_path / "build" / "new.txt"))
    assert snapshot.is_directory(str(tmp_path / "build"))
    assert generalise.nearest_existing(str(tmp_path / "build" / "new.txt"), snapshot) == str(tmp_path / "build")


def test_a_value_only_one_run_added_beside_stable_ones_does_not_change():
    grants, _ = generalise.per_run_grants([read("/proc/1/stat", run=1), read("/proc/1/stat", run=2),
                                           read("/proc/50/stat", run=2)])
    assert grants == {}


def test_a_listed_directory_no_policy_line_can_carry_leaves_no_comment():
    grants, notes = generalise.grants_and_notes([read("/etc/a#b")], snapshot_with(directories=("/etc/a#b",)), FINE)
    assert grants == {}
    assert notes.comments == {}


def execute(path: str) -> record.Denial:
    """A refused execution of one file."""
    return denial(path, "execute", operation="execve")


APP = snapshot_with("/srv/app/run.sh", "/srv/app/data/out.txt", "/srv/app/bin/tool",
                    directories=("/srv/app", "/srv/app/data", "/srv/app/bin"))


def test_an_executed_file_in_a_directory_without_a_write_right_still_widens_to_the_directory():
    grants, notes = generalise.grants_and_notes([execute("/srv/app/run.sh"), read("/srv/app/run.sh")], APP, FINE)
    assert grants == {"/srv/app": frozenset({"read", "execute"})}
    assert notes.reported == []


@pytest.mark.parametrize("write", [
    denial("/srv/app/new.txt", "create", operation="openat"),
    denial("/srv/app/data/out.txt", "write"),
])
def test_execute_stays_on_the_file_when_its_directory_or_an_entry_beneath_it_is_writable(write):
    grants, notes = generalise.grants_and_notes([execute("/srv/app/run.sh"), write], APP, FINE)
    assert grants["/srv/app/run.sh"] == frozenset({"execute"})
    assert "execute" not in grants.get("/srv/app", frozenset())
    assert "/srv/app overlaps a write-class right" in notes.comments["/srv/app/run.sh"]


def test_execute_stays_on_the_file_when_an_ancestor_of_its_directory_is_writable():
    grants, _ = generalise.grants_and_notes([execute("/srv/app/bin/tool"), create("/srv/app/new")], APP, FINE)
    assert grants == {"/srv/app/bin/tool": frozenset({"execute"}), "/srv/app": frozenset({"create"})}


def test_a_file_the_run_created_and_executed_in_a_writable_directory_is_reported_not_granted():
    grants, notes = generalise.grants_and_notes([execute("/srv/app/built"), create("/srv/app/built")], APP, FINE)
    assert grants == {"/srv/app": frozenset({"create"})}
    assert [(item["path"], item["section"]) for item in notes.reported] == [("/srv/app/built", "execute")]


def test_narrow_execute_on_a_whole_policy_takes_execute_off_a_directory_with_a_write_beneath_it():
    notes = generalise.Notes()
    narrowed = generalise.narrow_execute({"/srv/app": frozenset({"read", "execute"}),
                                          "/srv/app/data": frozenset({"write", "create"})},
                                         ["/srv/app/run.sh"], APP, notes)
    assert narrowed == {"/srv/app": frozenset({"read"}), "/srv/app/run.sh": frozenset({"execute"}),
                        "/srv/app/data": frozenset({"write", "create"})}
    assert "/srv/app overlaps a write-class right" in notes.comments["/srv/app/run.sh"]


def test_executable_siblings_are_not_compacted_into_a_directory_that_overlaps_a_write():
    siblings = {"/srv/app/a": frozenset({"execute"}), "/srv/app/b": frozenset({"execute"}),
                "/srv/app/c": frozenset({"execute"})}
    assert generalise.compact(siblings, 3, FINE) == {"/srv/app": frozenset({"execute"})}
    writable = {**siblings, "/srv/app/cache": frozenset({"create"})}
    assert generalise.compact(writable, 3, FINE) == writable


BESIDE = snapshot_with("/srv/app/run.sh", "/srv/app/bin/tool", "/srv/app/data/out.txt", "/srv/app-data/x",
                       "/srv/app/we#ird", directories=("/srv/app", "/srv/app/bin", "/srv/app/data", "/srv/app-data"))


def test_a_write_beside_the_executed_directory_leaves_its_execute_where_it_was():
    grants, notes = generalise.grants_and_notes([execute("/srv/app/bin/tool"), denial("/srv/app/data/out.txt", "write")],
                                                BESIDE, FINE)
    assert grants == {"/srv/app/bin": frozenset({"execute"}), "/srv/app/data/out.txt": frozenset({"write"})}
    assert notes.comments == {}


def test_a_write_in_a_directory_that_only_shares_a_prefix_does_not_overlap():
    grants, _ = generalise.grants_and_notes([execute("/srv/app/run.sh"), denial("/srv/app-data/x", "write")],
                                            BESIDE, FINE)
    assert grants["/srv/app"] == frozenset({"execute"})


def test_an_execute_on_the_writable_directory_itself_is_reported_not_granted():
    grants, notes = generalise.grants_and_notes([execute("/srv/app"), create("/srv/app/new")], BESIDE, FINE)
    assert grants == {"/srv/app": frozenset({"create"})}
    assert ("/srv/app", "execute") in [(item["path"], item["section"]) for item in notes.reported]


def test_read_siblings_still_compact_into_a_directory_that_overlaps_a_write():
    grants = {"/srv/app/a": frozenset({"read"}), "/srv/app/b": frozenset({"read"}), "/srv/app/c": frozenset({"read"}),
              "/srv/app/cache": frozenset({"create"})}
    assert generalise.compact(grants, 3, FINE) == {"/srv/app": frozenset({"read"}),
                                                   "/srv/app/cache": frozenset({"create"})}


def test_an_executed_name_no_policy_line_can_carry_is_reported_when_its_widening_is_withdrawn():
    grants, notes = generalise.grants_and_notes([execute("/srv/app/we#ird"), create("/srv/app/new")], BESIDE, FINE)
    assert grants == {"/srv/app": frozenset({"create"})}
    assert any(item["path"] == "/srv/app/we#ird" and "withdrawn" in item["reason"] for item in notes.reported)


def test_a_file_a_deeper_directory_still_lets_execute_is_not_moved_and_the_result_renders():
    denials = [execute("/srv/app/run.sh"), read("/srv/app/run.sh"), execute("/srv/app/bin/tool"),
               read("/srv/app/bin/tool"), create("/srv/app/data/new")]
    grants, notes = generalise.grants_and_notes(denials, BESIDE, FINE)
    assert grants == {"/srv/app": frozenset({"read"}), "/srv/app/run.sh": frozenset({"execute"}),
                      "/srv/app/bin": frozenset({"read", "execute"}), "/srv/app/data": frozenset({"create"})}
    assert set(notes.comments) == {"/srv/app/run.sh"}
    generalise.cfgfile.check_hierarchy(grants)


def test_an_executable_the_run_created_is_reported_even_where_no_write_was_refused():
    grants, notes = generalise.grants_and_notes([execute("/srv/app/gen/tool")], BESIDE, FINE)
    assert grants == {}
    assert [(item["path"], item["section"]) for item in notes.reported] == [("/srv/app/gen/tool", "execute")]


def test_a_write_class_right_of_the_policy_the_grants_are_layered_on_counts_too():
    grants, _ = generalise.grants_and_notes([execute("/srv/app/run.sh")], BESIDE, FINE,
                                            held={"/srv/app/data": frozenset({"write"})})
    assert grants == {"/srv/app/run.sh": frozenset({"execute"})}
    siblings = {"/srv/app/a": frozenset({"execute"}), "/srv/app/b": frozenset({"execute"}),
                "/srv/app/c": frozenset({"execute"})}
    assert generalise.compact(siblings, 3, FINE, held={"/srv/app": frozenset({"create"})}) == siblings


def test_a_kept_file_that_can_itself_be_written_says_so():
    grants, notes = generalise.grants_and_notes([execute("/srv/app/run.sh"), denial("/srv/app/run.sh", "write")],
                                                BESIDE, FINE)
    assert grants == {"/srv/app/run.sh": frozenset({"write", "execute"})}
    assert notes.comments["/srv/app/run.sh"].endswith("can be overwritten in place")


def test_the_comment_names_the_deepest_narrowed_directory():
    tree = snapshot_with("/srv/app/sub/x/tool", directories=("/srv/app", "/srv/app/sub", "/srv/app/sub/x"))
    notes = generalise.Notes()
    generalise.narrow_execute({"/srv/app": frozenset({"execute"}), "/srv/app/sub/x": frozenset({"execute", "create"})},
                              ["/srv/app/sub/x/tool"], tree, notes)
    assert "because /srv/app/sub/x overlaps" in notes.comments["/srv/app/sub/x/tool"]


def test_an_executable_a_held_write_lets_the_run_overwrite_is_noted_wherever_it_was_placed():
    tree = snapshot_with("/root/.gradle/dist/bin/gradle", directories=("/root/.gradle", "/root/.gradle/dist/bin"))
    grants, notes = generalise.grants_and_notes([execute("/root/.gradle/dist/bin/gradle")], tree, FINE,
                                                held={"/root/.gradle": frozenset({"write"})})
    assert grants == {"/root/.gradle/dist/bin/gradle": frozenset({"execute"})}
    assert notes.comments["/root/.gradle/dist/bin/gradle"] == generalise.EXECUTE_WRITABLE_COMMENT
    assert generalise.grants_for([execute("/root/.gradle/dist/bin/gradle")], tree, FINE) == grants


def test_a_kept_file_under_a_held_write_says_so():
    grants, notes = generalise.grants_and_notes([execute("/srv/app/run.sh")], BESIDE, FINE,
                                                held={"/srv/app": frozenset({"write"})})
    assert grants == {"/srv/app/run.sh": frozenset({"execute"})}
    assert notes.comments["/srv/app/run.sh"].endswith("can be overwritten in place")


def test_narrow_execute_on_a_whole_policy_reports_an_executed_object_that_did_not_exist():
    notes = generalise.Notes()
    narrowed = generalise.narrow_execute({"/srv/app": frozenset({"execute", "create"})}, ["/srv/app/gen/tool"],
                                         BESIDE, notes)
    assert narrowed == {"/srv/app": frozenset({"create"})}
    assert [(item["path"], item["section"]) for item in notes.reported] == [("/srv/app/gen/tool", "execute")]


def test_an_execute_already_on_the_file_is_left_alone_without_a_comment():
    snapshot = snapshot_with("/home/u/bin/tool", directories=("/home/u", "/home/u/bin"))
    grants, notes = generalise.grants_and_notes([execute("/home/u/bin/tool"), create("/home/u/bin/new")], snapshot, FINE)
    assert grants == {"/home/u/bin/tool": frozenset({"execute"}), "/home/u/bin": frozenset({"create"})}
    assert notes.comments == {}


@pytest.mark.parametrize("directory", ["/var/tmp", "/var"])
def test_a_creation_in_a_directory_phobos_s_specification_lies_beneath_is_reported_not_granted(directory):
    tree = snapshot_with(directories=("/var", "/var/tmp", "/tmp"))
    grants, notes = generalise.grants_and_notes([create(directory), create("/tmp")], tree, FINE)
    assert grants == {"/tmp": frozenset({"create"})}
    assert [(item["path"], item["section"]) for item in notes.reported] == [(directory, "create")]


def test_writing_beneath_the_specification_s_parent_or_reading_it_is_still_granted():
    tree = snapshot_with(directories=("/var", "/var/tmp", "/var/tmp/testing-dir"))
    grants, notes = generalise.grants_and_notes([create("/var/tmp/testing-dir"), read("/var/tmp"), create("/")],
                                                tree, FINE)
    assert grants == {"/var/tmp/testing-dir": frozenset({"create"}), "/var/tmp": frozenset({"read"})}
    assert [(item["path"], item["section"]) for item in notes.reported] == [("/", "create")]
    assert generalise.SPECIFICATION_ANCESTORS == ("/var/tmp", "/var", "/")


def need(path: str, section: str = "read", tid: int = 300, tgid: int = 300, run: int = 1) -> record.Need:
    """A need of one section on one path, read from an openat."""
    return record.Need(objects=(path,), sections=frozenset({section}), run=run, tid=tid, tgid=tgid,
                       evidence=f"{tid} openat()")


def test_a_denial_and_a_need_generalise_alike():
    refused = read("/usr/lib/jvm/lib/modules")
    snapshot = snapshot_with("/usr/lib/jvm/lib", "/usr/lib/jvm/lib/modules")
    assert generalise.grants_for([refused], snapshot, FINE) == generalise.grants_for([refused.need()], snapshot, FINE)


def test_another_process_of_the_session_is_a_per_run_name_from_one_run():
    grants, comments = generalise.per_run_grants([need("/proc/977/status")], own_ids=frozenset({300, 977}))
    assert grants == {"/proc": frozenset({"read"})}
    assert comments["/proc"].startswith("per-run name: /proc/<pid>/status")


def test_a_process_outside_the_session_seen_once_is_not_taken_as_per_run():
    grants, _ = generalise.per_run_grants([need("/proc/1/cmdline")], own_ids=frozenset({300}))
    assert grants == {}


def test_a_process_outside_the_session_seen_once_is_granted_file_by_file():
    snapshot = snapshot_with("/proc/1/cmdline", "/proc/1")
    grants = generalise.grants_for([need("/proc/1/cmdline")], snapshot, FINE, own_ids=frozenset({300}))
    assert grants == {"/proc/1/cmdline": frozenset({"read"})}


def test_a_session_process_is_left_to_the_per_run_grant_by_grants_for():
    snapshot = snapshot_with("/proc/977/status", "/proc/977")
    assert generalise.grants_for([need("/proc/977/status")], snapshot, FINE, own_ids=frozenset({977})) == {}
