"""Checks that a policy is written as phobos-policysystem.sh reads it, refused where it would refuse, and read back."""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile


def policy(fs: dict[str, set[str]] | None = None, connect: tuple[str, ...] = (), bind: tuple[str, ...] = (),
           limits: dict[str, int] | None = None, comments: dict[str, str] | None = None) -> cfgfile.Policy:
    """A policy from plain sets."""
    return cfgfile.Policy(fs={path: frozenset(sections) for path, sections in (fs or {}).items()},
                          connect=connect, bind=bind, limits=limits or {}, comments=comments or {})


def test_sections_come_in_a_fixed_order_with_sorted_paths_and_a_final_newline():
    text = cfgfile.render(policy({"/usr": {"read", "execute"}, "/opt": {"read"}, "/w/build": {"create", "write"}},
                                 connect=("allow 127.0.0.1:*",), bind=("allow 0",), limits={"cpu": 30, "timeout": 60}))
    assert text == ("[read]\n/opt\n/usr\n\n[execute]\n/usr\n\n[write]\n/w/build\n\n[create]\n/w/build\n\n"
                    "[connect]\nallow 127.0.0.1:*\n\n[bind]\nallow 0\n\n[limits]\ntimeout=60\ncpu=30\n")


def test_limits_off_writes_zero_for_every_limit():
    text = cfgfile.render(policy(limits={"timeout": 0, "cpu": 0, "mem_mb": 0, "nproc": 0, "nofile": 0, "fsize_mb": 0}))
    assert "timeout=0" in text
    assert "mem_mb=0" in text


def test_a_comment_is_written_once_above_the_first_line_of_its_path():
    text = cfgfile.render(policy({"/proc": {"read", "execute"}}, comments={"/proc": "per-run name: /proc/<pid>/stat"}))
    assert text == "[read]\n# per-run name: /proc/<pid>/stat\n/proc\n\n[execute]\n/proc\n"


@pytest.mark.parametrize("path", ["relative/path", "/srv/a*", "/srv/a?", "/srv/a[1]", "/srv/a\nb", "/srv/a\rb",
                                  "/srv/a#b", "/srv/a ", "/srv/a\x1bb"])
def test_a_path_the_parser_would_refuse_or_misread_is_refused(path):
    with pytest.raises(ValueError):
        cfgfile.render(policy({path: {"read"}}))


def test_a_nested_strict_subset_is_refused_and_different_rights_are_not():
    with pytest.raises(ValueError):
        cfgfile.render(policy({"/usr": {"read", "execute"}, "/usr/bin": {"read"}}))
    with pytest.raises(ValueError):
        cfgfile.render(policy({"/w": {"restructure"}, "/w/a": {"create"}}))
    assert cfgfile.render(policy({"/usr": {"read", "execute"}, "/usr/out": {"write"}}))
    assert cfgfile.render(policy({"/usr": {"read"}, "/usrlocal": {"write"}}))


def test_a_rule_or_comment_that_a_hash_or_a_line_break_would_cut_is_refused():
    with pytest.raises(ValueError):
        cfgfile.render(policy(connect=("allow 127.0.0.1:* # x",)))
    with pytest.raises(ValueError):
        cfgfile.render(policy({"/proc": {"read"}}, comments={"/proc": "x\n[write]\n/"}))
    with pytest.raises(ValueError):
        cfgfile.render(policy(limits={"memory": 5}))


def test_a_rendered_policy_reads_back_as_itself():
    original = policy({"/usr": {"read", "execute"}, "/w": {"restructure", "create-ipc"}, "/dev/null": {"read", "write"}},
                      connect=("allow localhost",), bind=("allow 0", "allow 0 udp"), limits={"nofile": 256},
                      comments={"/w": "a reason"})
    again = cfgfile.read_policy(cfgfile.render(original))
    assert again.fs == original.fs
    assert (again.connect, again.bind, again.limits) == (original.connect, original.bind, original.limits)
    assert again.comments == {}


def test_reading_refuses_what_the_parser_refuses():
    with pytest.raises(ValueError):
        cfgfile.read_policy("/usr\n")
    with pytest.raises(ValueError):
        cfgfile.read_policy("[accept]\nallow 80\n")
    with pytest.raises(ValueError):
        cfgfile.read_policy("[limits]\nmemory=5\n")


def test_remainder_drops_what_the_base_grants_along_the_ancestors_and_keeps_new_rights():
    base = policy({"/usr": {"read", "execute"}, "/w": {"write"}}, connect=("allow localhost",), bind=("allow 0",))
    exercise = policy({"/usr/lib/jvm": {"read"}, "/usr/share/x": {"read", "write"}, "/w/a": {"write", "delete"},
                       "/srv/data": {"read"}},
                      connect=("allow localhost", "allow 127.0.0.1:5432"), bind=("allow 0",), limits={"cpu": 30},
                      comments={"/usr/lib/jvm": "dropped", "/srv/data": "kept"})
    rest = cfgfile.remainder(exercise, base)
    assert rest.fs == {"/usr/share/x": frozenset({"write"}), "/w/a": frozenset({"delete"}),
                       "/srv/data": frozenset({"read"})}
    assert rest.connect == ("allow 127.0.0.1:5432",)
    assert rest.bind == ()
    assert rest.limits == {"cpu": 30}
    assert rest.comments == {"/srv/data": "kept"}


def test_the_permissive_policy_keeps_the_specification_parent_out_of_every_write_path(tmp_path):
    for name in ("usr", "tmp", "var/tmp", "var/lib", "proc", "run", "dev", "sys", "root"):
        (tmp_path / name).mkdir(parents=True)
    (tmp_path / "bin").symlink_to("usr")
    result = cfgfile.permissive_policy(tmp_path, ("api.example.org:443",))
    writable = {path for path, sections in result.fs.items() if "write" in sections}
    assert writable == {"/root", "/tmp", "/usr", "/var/lib", "/var/tmp/testing-dir", "/dev/null"}
    assert result.fs["/"] == frozenset({"read", "execute"})
    assert "allow api.example.org:443" in result.connect
    assert [rule for rule in result.connect if "example" in rule] == ["allow api.example.org:443"]
    assert cfgfile.render(result)


def test_the_permissive_policy_of_the_real_root_never_writes_the_root_or_var_tmp():
    result = cfgfile.permissive_policy(pathlib.Path("/"))
    assert not any(path in ("/", "/var", "/var/tmp", "/run") for path, sections in result.fs.items() if "write" in sections)
