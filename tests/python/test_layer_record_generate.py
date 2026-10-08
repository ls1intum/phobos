"""Checks how recorded sessions become a policy: the grants, the widenings, the header and the gate (plan A.7).

Each case writes a recording directory the way phobos-record record would (a trace, a session.json
and a snapshot), generates from it, and reads the policy back through the parser's reader.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, generalise
from layer_record import generate


def listing_of(*paths: str, directories: tuple[str, ...] = ()) -> str:
    """A snapshot listing holding the given files and directories, in the form snapshot.take writes."""
    lines = {"/": "d 0755"}
    for directory in directories:
        lines[directory] = "d 0755"
    for path in paths:
        lines[path] = "f 0644 1 1700000000000000000"
    return "".join(f"{value}\t{path}\n" for path, value in sorted(lines.items()))


def recording_directory(tmp_path: pathlib.Path, *sessions: list[str], listing: str, containers: int = 1,
                        interactive: bool = False) -> pathlib.Path:
    """A recording directory with one session per list of trace lines, all in the container whose listing is given."""
    root = tmp_path / "recording"
    (root / "snapshots").mkdir(parents=True)
    for index in range(containers):
        (root / "snapshots" / f"c{index}.txt").write_text(listing, encoding="utf-8")
    for number, lines in enumerate(sessions, start=1):
        directory = root / "sessions" / str(number)
        directory.mkdir(parents=True)
        (directory / "trace").write_text("\n".join(lines) + "\n", encoding="utf-8")
        meta = {"command": ["tool"], "started": "2026-10-05T10:00:00Z", "status": 0, "interactive": interactive,
                "container_id": f"c{min(number - 1, containers - 1)}", "snapshot": f"snapshots/c{min(number - 1, containers - 1)}.txt",
                "workdir": "/opt/w", "landlock_abi": 8, "strace": "6.8"}
        (directory / "session.json").write_text(json.dumps(meta), encoding="utf-8")
    return root


def accepting(path: pathlib.Path) -> tuple[int, str]:
    """A gate that accepts every policy, for a unit test that has no image."""
    return 0, ""


def generated(tmp_path: pathlib.Path, *sessions: list[str], listing: str, **keywords) -> tuple[int, cfgfile.Policy, dict]:
    """Generates and answers the status, the policy read back and record.json."""
    root = recording_directory(tmp_path, *sessions, listing=listing, **keywords)
    status = generate.write(root, with_limits=False, memory_pinned=False, gate=accepting)
    policy = cfgfile.read_policy((root / "policy.cfg").read_text(encoding="utf-8"))
    return status, policy, json.loads((root / "record.json").read_text(encoding="utf-8"))


OPEN_HOSTNAME = '16 openat(AT_FDCWD</opt/w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>'


def test_a_file_in_a_fine_grained_root_stays_a_file(tmp_path):
    status, policy, _ = generated(tmp_path, [OPEN_HOSTNAME], listing=listing_of("/etc/hostname", directories=("/etc", "/opt/w")))
    assert status == 0
    assert policy.fs == {"/etc/hostname": frozenset({"read"})}


def test_a_file_created_and_read_back_is_granted_on_its_pre_existing_parent(tmp_path):
    lines = ['16 openat(AT_FDCWD</opt/w>, "/opt/w/x", O_WRONLY|O_CREAT, 0666) = 3</opt/w/x>',
             '16 openat(AT_FDCWD</opt/w>, "/opt/w/x", O_RDONLY) = 3</opt/w/x>']
    _, policy, _ = generated(tmp_path, lines, listing=listing_of(directories=("/opt", "/opt/w")))
    assert policy.fs == {"/opt/w": frozenset({"create", "write", "read"})}


def test_a_read_of_a_path_the_session_created_is_never_written_as_that_path(tmp_path):
    lines = ['16 openat(AT_FDCWD</opt/w>, "/opt/w/cache/x", O_WRONLY|O_CREAT, 0666) = 3</opt/w/cache/x>',
             '16 openat(AT_FDCWD</opt/w>, "/opt/w/cache/x", O_RDONLY) = 3</opt/w/cache/x>']
    _, policy, _ = generated(tmp_path, lines, listing=listing_of(directories=("/opt", "/opt/w")))
    assert all(path in ("/opt/w", "/opt/w/cache") for path in policy.fs)
    assert "/opt/w/cache/x" not in policy.fs


def test_a_listed_directory_in_a_fine_grained_root_gets_read_and_a_comment_that_says_what_that_opens(tmp_path):
    lines = ['16 openat(AT_FDCWD</opt/w>, "/etc/ssl/certs", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3</etc/ssl/certs>']
    root = recording_directory(tmp_path, lines, listing=listing_of(
        "/etc/ssl/certs/a.pem", directories=("/etc", "/etc/ssl", "/etc/ssl/certs", "/opt/w")))
    assert generate.write(root, False, False, accepting) == 0
    text = (root / "policy.cfg").read_text(encoding="utf-8")
    assert "# listed: [read] on the directory /etc/ssl/certs makes every entry beneath it readable" in text
    widening = json.loads((root / "record.json").read_text(encoding="utf-8"))["widenings"]
    assert any(item["path"] == "/etc/ssl/certs" and item["files_beneath"] == 1 for item in widening)


def test_a_file_read_in_a_fine_grained_root_gets_no_listing_comment(tmp_path):
    root = recording_directory(tmp_path, [OPEN_HOSTNAME], listing=listing_of("/etc/hostname", directories=("/etc", "/opt/w")))
    generate.write(root, False, False, accepting)
    assert "listed:" not in (root / "policy.cfg").read_text(encoding="utf-8")


def test_a_file_name_with_a_carriage_return_is_granted_on_its_parent(tmp_path):
    lines = ['16 openat(AT_FDCWD</opt/w>, "/srv/data/a\\rb", O_RDONLY) = 3</srv/data/a\\rb>']
    _, policy, _ = generated(tmp_path, lines, listing=listing_of("/srv/data/a\rb", directories=("/srv", "/srv/data", "/opt/w")))
    assert policy.fs == {"/srv/data": frozenset({"read"})}


def test_a_move_gives_the_source_every_section_of_the_destination():
    grants = {"/tmp": frozenset({"create", "delete", "restructure"}), "/opt/w": frozenset({"read", "create", "restructure"})}
    widened, withheld = generate.source_covers_destination(grants, {("/tmp", "/opt/w")})
    assert widened["/tmp"] >= widened["/opt/w"]
    assert withheld == []


def test_a_chain_of_moves_settles():
    grants = {"/a": frozenset({"restructure"}), "/b": frozenset({"restructure", "write"}),
              "/c": frozenset({"restructure", "read"})}
    widened, _ = generate.source_covers_destination(grants, {("/a", "/b"), ("/b", "/c")})
    assert {"write", "read"} <= widened["/a"]


def test_what_an_ancestor_grants_the_destination_counts_for_it():
    grants = {"/var/tmp": frozenset({"read"}), "/var/tmp/d": frozenset({"restructure"}), "/tmp": frozenset({"restructure"})}
    widened, _ = generate.source_covers_destination(grants, {("/tmp", "/var/tmp/d")})
    assert "read" in widened["/tmp"]


def test_execute_is_never_given_to_a_source_and_the_move_is_reported():
    grants = {"/d": frozenset({"execute", "restructure"}), "/s": frozenset({"delete", "restructure"})}
    widened, withheld = generate.source_covers_destination(grants, {("/s", "/d")})
    assert "execute" not in widened["/s"]
    assert withheld == [("/s", "/d", "execute")]


def test_no_read_or_execute_row_names_a_path_absent_before_the_sessions():
    recorded = generate.Recorded([{"/": "d 0755", "/opt/w": "d 0755"}])
    grants = {"/opt/w/new-file": frozenset({"read"}), "/opt/w": frozenset({"write"})}
    assert generate.missing_read_or_execute(grants, recorded) == ["/opt/w/new-file"]


def test_a_cross_directory_move_is_recorded_and_the_source_gets_the_destinations_sections(tmp_path):
    lines = ['16 openat(AT_FDCWD</opt/w>, "/opt/w/in.txt", O_RDONLY) = 3</opt/w/in.txt>',
             '16 renameat2(AT_FDCWD</opt/w>, "/srv/s/a", AT_FDCWD</opt/w>, "/opt/w/b", 0) = 0']
    _, policy, _ = generated(tmp_path, lines, listing=listing_of("/srv/s/a", "/opt/w/in.txt", directories=("/srv", "/srv/s", "/opt", "/opt/w")))
    assert "restructure" in policy.fs["/srv/s"]
    assert "restructure" in policy.fs["/opt/w"]
    assert "delete" in policy.fs["/srv/s"]


def test_an_unsupported_call_makes_generate_say_incomplete(tmp_path):
    lines = ['16 openat(AT_FDCWD</opt/w>, "/opt/w", O_RDWR|O_TMPFILE, 0600) = 3</opt/w/#1 (deleted)>']
    root = recording_directory(tmp_path, lines, listing=listing_of(directories=("/opt/w",)))
    assert generate.write(root, False, False, accepting) == generate.EXIT_INCOMPLETE
    assert "INCOMPLETE: 1 recorded calls are not mapped" in (root / "policy.cfg").read_text(encoding="utf-8")
    assert json.loads((root / "record.json").read_text(encoding="utf-8"))["unsupported"]


def test_the_gate_refusing_the_policy_is_reported_and_the_files_stay(tmp_path):
    root = recording_directory(tmp_path, [OPEN_HOSTNAME], listing=listing_of("/etc/hostname", directories=("/etc", "/opt/w")))
    assert generate.write(root, False, False, lambda path: (11, "Policy invalid")) == generate.EXIT_GATE
    assert (root / "policy.cfg").is_file()


def test_the_header_says_what_the_file_is_and_what_it_does_not_cover(tmp_path):
    root = recording_directory(tmp_path, [OPEN_HOSTNAME], listing=listing_of("/etc/hostname", directories=("/etc", "/opt/w")))
    generate.write(root, False, False, accepting)
    text = (root / "policy.cfg").read_text(encoding="utf-8")
    assert text.startswith("# Recorded by phobos-record, not pruned. Sessions merged: 1 (2026-10-05).\n")
    assert "never record an untrusted submission" in text
    assert "Limits: none derived" in text


def test_a_fixed_refusal_is_a_trailing_comment_and_never_a_grant(tmp_path):
    lines = ['16 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 110) = 0',
             "16 setsid() = 16"]
    root = recording_directory(tmp_path, lines, listing=listing_of(directories=("/opt/w",)))
    assert generate.write(root, False, False, accepting) == 0
    text = (root / "policy.cfg").read_text(encoding="utf-8")
    assert "# Grading refuses this whatever a policy grants: connection to the UNIX socket" in text
    assert "/run/dbus" not in cfgfile.render(cfgfile.read_policy(text)).replace("# ", "")
    assert json.loads((root / "record.json").read_text(encoding="utf-8"))["fixed_refusals"]


def test_two_sessions_are_merged_into_the_union_of_what_each_needed(tmp_path):
    first = [OPEN_HOSTNAME]
    second = ['16 openat(AT_FDCWD</opt/w>, "/etc/os-release", O_RDONLY) = 3</etc/os-release>']
    status, policy, _ = generated(tmp_path, first, second, containers=2,
                                  listing=listing_of("/etc/hostname", "/etc/os-release", directories=("/etc", "/opt/w")))
    assert status == 0
    assert set(policy.fs) == {"/etc/hostname", "/etc/os-release"}


def test_a_process_of_the_session_in_proc_is_a_per_run_name_from_one_session(tmp_path):
    lines = ["16 clone(child_stack=NULL, flags=SIGCHLD) = 17",
             '16 openat(AT_FDCWD</opt/w>, "/proc/17/status", O_RDONLY) = 3</proc/17/status>']
    _, policy, _ = generated(tmp_path, lines, listing=listing_of(directories=("/opt/w",)))
    assert policy.fs == {"/proc": frozenset({"read"})}


def test_sessions_from_two_images_are_refused(tmp_path):
    root = recording_directory(tmp_path, [OPEN_HOSTNAME], [OPEN_HOSTNAME], containers=2,
                               listing=listing_of("/usr/bin/tool", directories=("/etc", "/opt/w")))
    (root / "snapshots" / "c1.txt").write_text(listing_of("/usr/bin/tool", "/usr/bin/other", directories=("/etc", "/opt/w")),
                                               encoding="utf-8")
    with pytest.raises(generate.ImageMismatch):
        generate.load(root)


def test_the_snapshot_of_the_second_container_judges_the_second_session(tmp_path):
    first = ['16 openat(AT_FDCWD</opt/w>, "/opt/w/made", O_WRONLY|O_CREAT, 0666) = 3</opt/w/made>']
    second = ['16 openat(AT_FDCWD</opt/w>, "/opt/w/made", O_RDONLY) = 3</opt/w/made>']
    root = recording_directory(tmp_path, first, second, containers=2, listing=listing_of(directories=("/opt/w", "/var")))
    status = generate.write(root, False, False, accepting)
    policy = cfgfile.read_policy((root / "policy.cfg").read_text(encoding="utf-8"))
    assert status == 0
    assert "/opt/w/made" not in policy.fs


def test_a_loopback_server_and_its_client_become_the_wildcard_and_a_bind_rule(tmp_path):
    lines = ['16 bind(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
             "16 listen(3<TCP:[127.0.0.1:40623]>, 128) = 0",
             '17 connect(4<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(40623), sin_addr=inet_addr("127.0.0.1")}, 16) = 0']
    _, policy, record = generated(tmp_path, lines, listing=listing_of(directories=("/opt/w",)))
    assert policy.connect == ("allow 127.0.0.1:*",)
    assert policy.bind == ("allow 0",)
    assert record["network"]["connect"][0]["rule"] == "allow 127.0.0.1:*"


def test_a_host_name_rule_adds_the_resolver_line_to_the_header(tmp_path):
    answer = (REPO_ROOT / "tests" / "python" / "fixtures" / "record" / "hello-sni.bin").read_bytes()
    hello = '"' + "".join(f"\\x{byte:02x}" for byte in answer) + '"'
    lines = ['16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0',
             f"16 write(3<TCP:[172.17.0.2:32972->93.184.216.34:443]>, {hello}, 517) = 517"]
    root = recording_directory(tmp_path, lines, listing=listing_of(directories=("/opt/w",)))
    generate.write(root, False, False, accepting)
    text = (root / "policy.cfg").read_text(encoding="utf-8")
    assert "allow example.org:443" in text
    assert "# This policy needs --resolver" in text


def test_the_policy_the_generator_writes_passes_the_policy_checks(tmp_path):
    lines = [OPEN_HOSTNAME, '16 openat(AT_FDCWD</opt/w>, "/opt/w/x", O_WRONLY|O_CREAT, 0666) = 3</opt/w/x>']
    root = recording_directory(tmp_path, lines, listing=listing_of("/etc/hostname", directories=("/etc", "/opt/w", "/var")))
    generate.write(root, False, False, accepting)
    policy = cfgfile.read_policy((root / "policy.cfg").read_text(encoding="utf-8"))
    cfgfile.check_policy(policy)
    assert generalise.normalise_hierarchy(policy.fs) == policy.fs


def test_an_interactive_session_derives_no_timeout_and_says_so():
    values, header = generate.derived_limits([{"interactive": True}], [measurement(wall=600.0, cpu=12.0)], False)
    assert "timeout" not in values
    assert any("wall clock" in line for line in header)


def test_only_batch_sessions_derive_a_timeout_with_the_shared_margin():
    values, _ = generate.derived_limits([{"interactive": False}], [measurement(wall=41.0, cpu=12.0)], False)
    assert values["timeout"] == 210


def test_memory_only_when_the_instructor_says_it_is_pinned():
    values, header = generate.derived_limits([{"interactive": False}], [measurement(wall=1.0, cpu=1.0, vm=2300.0)], False)
    assert "mem_mb" not in values
    assert any("mem_mb" in line for line in header)
    pinned, _ = generate.derived_limits([{"interactive": False}], [measurement(wall=1.0, cpu=1.0, vm=2300.0)], True)
    assert pinned["mem_mb"] == 4608


def test_without_a_sampled_session_no_limit_is_derived():
    assert generate.derived_limits([{"interactive": False}], [], False)[0] == {}


def test_limits_are_written_when_asked_for_and_a_session_was_sampled(tmp_path):
    root = recording_directory(tmp_path, [OPEN_HOSTNAME], listing=listing_of("/etc/hostname", directories=("/etc", "/opt/w")))
    (root / "sessions" / "1" / "samples.json").write_text(json.dumps({
        "wall_seconds": 3.0, "largest_file_mb": 0.0,
        "samples": [{"pid": 5, "vm_peak_mb": 100.0, "cpu_seconds": 1.0, "highest_descriptor": 9, "tasks": 3, "time": 0.1}]}),
        encoding="utf-8")
    assert generate.write(root, True, False, accepting) == 0
    policy = cfgfile.read_policy((root / "policy.cfg").read_text(encoding="utf-8"))
    assert policy.limits["nofile"] == 256
    assert policy.limits["timeout"] == 60


def measurement(wall: float, cpu: float, vm: float = 100.0):
    """A measurement of one sampled session with the peaks given."""
    from layer_prune import limits
    return limits.Measurement(wall_seconds=wall, cpu_seconds=cpu, vm_peak_mb=vm, tasks=1, highest_descriptor=3,
                              largest_file_mb=0.0)
