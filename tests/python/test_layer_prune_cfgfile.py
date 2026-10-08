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


@pytest.mark.parametrize("path", ["/srv/x\x85/etc", "/srv/x\u2028/etc", "/srv/x\u2029/etc", "/srv/x\x0b/etc",
                                  "/a/../etc", "/usr/", "//usr", "/usr/./bin"])
def test_a_path_another_reader_would_split_or_that_is_not_normal_is_refused(path):
    with pytest.raises(ValueError):
        cfgfile.render(policy({path: {"read"}}))


@pytest.mark.parametrize("text", ["[read]\r\n/usr\r\n", "[limits]\ncpu=\u0661\u0662\n"])
def test_reading_refuses_what_the_parser_refuses_in_its_own_way(text):
    with pytest.raises(ValueError):
        cfgfile.read_policy(text)


def test_reading_splits_only_at_lf_trims_only_what_bash_trims_and_never_splits_a_path_in_two():
    assert set(cfgfile.read_policy("[read]\n /srv/c\t\n").fs) == {"/srv/c"}
    for path in ("/srv/a\x85/etc", "/srv/a\u2028/etc", "/srv/d\xa0"):
        with pytest.raises(ValueError):
            cfgfile.read_policy(f"[read]\n{path}\n")


def test_a_limit_named_twice_is_merged_as_the_parser_merges_it():
    assert cfgfile.read_policy("[limits]\ncpu=30\ncpu=60\n").limits == {"cpu": 60}
    assert cfgfile.read_policy("[limits]\ncpu=0\ncpu=30\n").limits == {"cpu": 0}
    assert cfgfile.read_policy("[limits]\ncpu=30\ncpu=0\n").limits == {"cpu": 0}


@pytest.mark.parametrize("limits", [{"cpu": -5}, {"nproc": True}, {"cpu": 10 ** 18}, {"cpu": "30"}])
def test_a_limit_value_the_parser_refuses_is_refused(limits):
    with pytest.raises(ValueError):
        cfgfile.render(policy(limits=limits))


@pytest.mark.parametrize(("connect", "bind"), [(("deny all",), ()), ((), ("allow 99999",)), ((), ("allow 80 sctp",))])
def test_a_network_line_not_in_its_sections_shape_is_refused(connect, bind):
    with pytest.raises(ValueError):
        cfgfile.render(policy(connect=connect, bind=bind))


@pytest.mark.parametrize("text", ["[read]\nusr\n", "[read]\n/usr/*\n", "[read]\n/usr/a\x00b\n",
                                  "[limits]\ncpu=1234567890123456789\n", "[limits]\nmem_mb=8796093022208\n"])
def test_reading_refuses_a_path_or_limit_the_parser_refuses(text):
    with pytest.raises(ValueError):
        cfgfile.read_policy(text)


def test_the_permissive_network_is_loopback_port_zero_and_the_declared_hosts():
    opened = cfgfile.with_permissive_network(cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=("allow x:1",),
                                                            bind=("allow 9",), limits={}), ("api.example.org:443",))
    assert opened.connect == (*cfgfile.PERMISSIVE_CONNECT, "allow api.example.org:443")
    assert opened.bind == cfgfile.PERMISSIVE_BIND
    assert opened.fs == {"/usr": frozenset({"read"})}


def test_a_header_and_rule_comments_are_written_and_read_back_without_them():
    original = cfgfile.Policy(fs={"/var/tmp/testing-dir": frozenset({"read"})},
                              connect=(cfgfile.Rule("allow example.org:443", "TLS host name"),),
                              bind=("allow 0",), limits={}, header=("Recorded by phobos-record.",),
                              notes=("Grading will refuse: setsid",))
    text = cfgfile.render(original)
    assert text.startswith("# Recorded by phobos-record.\n")
    assert "# TLS host name\nallow example.org:443\n" in text
    assert text.rstrip().endswith("# Grading will refuse: setsid")
    again = cfgfile.read_policy(text)
    assert again.connect == ("allow example.org:443",)
    assert again.fs == original.fs


def test_a_comment_rule_is_written_as_a_comment_and_grants_nothing():
    text = cfgfile.render(cfgfile.Policy(fs={}, connect=("allow 127.0.0.1:*", "# not granted: lookup of x"),
                                         bind=(), limits={}))
    assert "# not granted: lookup of x\n" in text
    assert cfgfile.read_policy(text).connect == ("allow 127.0.0.1:*",)


def test_a_rule_comment_cannot_end_its_line_and_become_a_rule():
    original = cfgfile.Policy(fs={}, connect=(cfgfile.Rule("allow 127.0.0.1:*", "seen as evil\n[write]\n/"),),
                              bind=(), limits={})
    text = cfgfile.render(original)
    assert "\n[write]\n" not in text
    assert "seen as evil\\x0a[write]\\x0a/" in text
    assert cfgfile.read_policy(text).fs == {}


def test_a_header_and_a_note_cannot_end_their_line_either():
    text = cfgfile.render(cfgfile.Policy(fs={}, connect=(), bind=(), limits={}, header=("a\r\n[read]\n/",),
                                         notes=("b [write]",)))
    assert cfgfile.read_policy(text).fs == {}
    assert "\\xe2\\x80\\xa8" in text


@pytest.mark.parametrize("path", ["/tmp/a\rb", "/tmp/a\x1bb", "/tmp/a\x7fb", "/tmp/a\udcffb"])
def test_a_path_with_a_control_character_or_invalid_utf8_is_refused(path):
    with pytest.raises(ValueError):
        cfgfile.render(policy({path: {"read"}}))


def test_comment_text_writes_everything_but_printable_ascii_and_hash_as_hex():
    assert cfgfile.comment_text("a b\nc#dé") == "a b\\x0ac\\x23d\\xc3\\xa9"
