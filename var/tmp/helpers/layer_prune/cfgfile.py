"""A Phobos policy as data, written as the configuration file phobos-policysystem.sh reads, and read back.

`render` refuses, with ValueError, what would make the parser read another policy than the one
given, or refuse it on its face: a path that is relative or not in normal form, a wildcard character,
a `#` (the parser cuts a line there), any character that ends or corrupts a line, a network rule or a
limit not in its section's shape, and a nested entry whose rights are a strict subset of an
ancestor's (resolve_rights_hierarchy refuses it, because Landlock can never take a right away).
Paths are compared as written, so the caller passes them through os.path.realpath first; what only
the system can answer (whether a [read] path exists, a dangling link, the hierarchy after links are
resolved) is left to the phobos-policysystem.sh gate and the run, which refuse it with PHB-EPOLICY.

`read_policy` splits and trims lines exactly as phobos-policy-parse.sh does: lines end at LF only, a
carriage return is refused, and only the whitespace bash's [[:space:]] names is trimmed. Beyond the
parser, it refuses every path and limit render would refuse, so nothing it reads can be written back
as a different policy.
"""

from __future__ import annotations

import dataclasses
import pathlib
import posixpath
import re

from layer_prune import network

# The filesystem sections, in the order they are written.
FILESYSTEM_SECTIONS = ("read", "execute", "write", "create", "create-ipc", "create-symlink", "delete", "restructure")
# The rights letters each filesystem section grants, as phobos-policy-parse.sh and phobos-rights.sh
# translate them; [restructure] is create, delete and refer.
SECTION_RIGHTS = {
    "read": frozenset("r"),
    "execute": frozenset("x"),
    "write": frozenset("w"),
    "create": frozenset("m"),
    "create-ipc": frozenset("p"),
    "create-symlink": frozenset("l"),
    "delete": frozenset("d"),
    "restructure": frozenset("mdf"),
}
# The write-class sections, which the permissive policy grants wherever it grants writing.
WRITE_SECTIONS = ("write", "create", "create-ipc", "create-symlink", "delete", "restructure")
# The [limits] keys, in the order they are written.
LIMIT_KEYS = ("timeout", "cpu", "mem_mb", "nproc", "nofile", "fsize_mb")
# Characters a path may not hold: the parser takes wildcards literally, cuts a line at `#`, and a
# control character, or a character another reader of the file would take as a line break, would end
# or corrupt the line.
FORBIDDEN_PATH_CHARACTERS = re.compile("[*?\\[#\x00-\x1f\x7f\x85\u2028\u2029]")
FORBIDDEN_RULE_CHARACTERS = re.compile("[#\x00-\x1f\x7f\x85\u2028\u2029]")
# The shapes a [connect] and a [bind] line must have: allow, a destination or a port, a transport.
CONNECT_RULE = re.compile(r"allow [^\s]+(?: (?:tcp|udp))?")
BIND_RULE = re.compile(r"allow (?P<port>0|[1-9][0-9]{0,4})(?: (?:tcp|udp))?")
# The highest port, the most digits a limit may have (PHB_LARGEST_LIMIT_DIGITS), and the largest
# megabyte value the resource layer can apply (PHB_LARGEST_MEGABYTES).
PORT_MAXIMUM = 65535
LIMIT_DIGITS_MAXIMUM = 18
LARGEST_MEGABYTES = 8796093022207
MEGABYTE_LIMITS = ("mem_mb", "fsize_mb")
# The whitespace bash's [[:space:]] trims around a line, and the digits its [[:digit:]] accepts.
PARSER_WHITESPACE = " \t\n\v\f\r"
DIGITS = re.compile(r"[0-9]+")
# The top-level directories the permissive policy never grants writing on: the pseudo filesystems,
# /var (whose child /var/tmp holds the run's specification) and /run (which holds the candidate).
NEVER_WRITABLE_TOP_LEVEL = frozenset({"/var", "/proc", "/sys", "/dev", "/run"})
# The exercise's working directory, where the build writes.
TESTING_DIR = "/var/tmp/testing-dir"
# The loopback and port-0 rules the permissive policy holds, so no stage starts narrower than a
# build on its own machine.
PERMISSIVE_CONNECT = ("allow 127.0.0.1:*", "allow [::1]", "allow localhost")
PERMISSIVE_BIND = ("allow 0", "allow 0 udp")


@dataclasses.dataclass(frozen=True)
class Policy:
    """A policy: filesystem grants by path, [connect] and [bind] rules, [limits] values, and comments.

    `fs` maps an absolute path to the sections that grant it. `comments` maps a path to one line
    written as a comment above that path's first line, the reason a grant is wider than observed.
    """

    fs: dict[str, frozenset[str]]
    connect: tuple[str, ...]
    bind: tuple[str, ...]
    limits: dict[str, int]
    comments: dict[str, str] = dataclasses.field(default_factory=dict)


def rights_of(sections: frozenset[str]) -> frozenset[str]:
    """The rights letters a set of filesystem sections grants."""
    return frozenset().union(*(SECTION_RIGHTS[section] for section in sections))


def is_beneath(path: str, ancestor: str) -> bool:
    """Whether `path` lies strictly beneath `ancestor`, by components rather than by text prefix."""
    return path != ancestor and path.startswith(ancestor.rstrip("/") + "/")


def check_path(path: str) -> None:
    """Refuses a path the parser would refuse or misread, or one not in normal form (`..`, `//`, a trailing `/`)."""
    if not path.startswith("/"):
        raise ValueError(f"{path!r} is not an absolute path")
    if FORBIDDEN_PATH_CHARACTERS.search(path) or path != path.strip():
        raise ValueError(f"{path!r} holds a character a policy path cannot carry")
    if posixpath.normpath(path) != path or path.startswith("//"):
        raise ValueError(f"{path!r} is not in normal form")


def check_rule(rule: str) -> None:
    """Refuses a network rule or comment line that a `#` or a line-breaking character would cut or break."""
    if FORBIDDEN_RULE_CHARACTERS.search(rule):
        raise ValueError(f"{rule!r} holds a character a policy line cannot carry")


def check_network(policy: Policy) -> None:
    """Refuses a [connect] or [bind] line that is not in its section's shape."""
    for rule in policy.connect:
        if not CONNECT_RULE.fullmatch(rule):
            raise ValueError(f"{rule!r} is not a [connect] rule")
    for rule in policy.bind:
        match = BIND_RULE.fullmatch(rule)
        if match is None or int(match.group("port")) > PORT_MAXIMUM:
            raise ValueError(f"{rule!r} is not a [bind] rule")


def check_limits(limits: dict[str, int]) -> None:
    """Refuses an unknown limit, and a value that is not a whole number from 0 with at most 18 digits."""
    for key, value in limits.items():
        if key not in LIMIT_KEYS:
            raise ValueError(f"unknown limit {key!r}")
        if type(value) is not int or value < 0 or len(str(value)) > LIMIT_DIGITS_MAXIMUM:
            raise ValueError(f"limit {key}={value!r} is not a whole number from 0")
        if key in MEGABYTE_LIMITS and value > LARGEST_MEGABYTES:
            raise ValueError(f"limit {key}={value} is more megabytes than the resource layer can apply")


def check_hierarchy(fs: dict[str, frozenset[str]]) -> None:
    """Refuses a nested entry whose rights are a strict subset of an ancestor's (resolve_rights_hierarchy)."""
    for path, sections in fs.items():
        rights = rights_of(sections)
        for ancestor, ancestor_sections in fs.items():
            if is_beneath(path, ancestor) and rights < rights_of(ancestor_sections):
                raise ValueError(f"{path!r} would hold fewer rights than its ancestor {ancestor!r}")


def check_policy(policy: Policy) -> None:
    """Refuses a policy render would write in a shape the parser refuses or misreads."""
    for path, sections in policy.fs.items():
        check_path(path)
        unknown = set(sections) - set(FILESYSTEM_SECTIONS)
        if unknown:
            raise ValueError(f"{path!r} names unknown sections {sorted(unknown)}")
    check_hierarchy(policy.fs)
    for rule in policy.connect + policy.bind + tuple(policy.comments.values()):
        check_rule(rule)
    check_network(policy)
    check_limits(policy.limits)


def render(policy: Policy) -> str:
    """The policy as configuration text: sections in a fixed order, paths sorted, LF, a final newline."""
    check_policy(policy)
    blocks: list[str] = []
    commented: set[str] = set()
    for section in FILESYSTEM_SECTIONS:
        paths = sorted(path for path, sections in policy.fs.items() if section in sections)
        if not paths:
            continue
        lines = [f"[{section}]"]
        for path in paths:
            if path in policy.comments and path not in commented:
                lines.append(f"# {policy.comments[path]}")
                commented.add(path)
            lines.append(path)
        blocks.append("\n".join(lines))
    for section, rules in (("connect", policy.connect), ("bind", policy.bind)):
        if rules:
            blocks.append("\n".join([f"[{section}]", *rules]))
    limit_lines = [f"{key}={policy.limits[key]}" for key in LIMIT_KEYS if key in policy.limits]
    if limit_lines:
        blocks.append("\n".join(["[limits]", *limit_lines]))
    return "\n\n".join(blocks) + "\n" if blocks else ""


def read_policy(text: str) -> Policy:
    """Reads configuration text back into a Policy, the inverse of render; comments are dropped.

    Lines are read as phobos-policy-parse.sh reads them: everything from a `#` is a comment, and the
    whitespace bash's [[:space:]] names is trimmed. A line outside any section, an unknown section, a
    filesystem line check_path refuses and a malformed limit raise ValueError. [accept] rules are not
    part of a Policy and are refused.
    """
    if "\r" in text:
        raise ValueError("a carriage return would become part of a value; the parser refuses it")
    fs: dict[str, set[str]] = {}
    connect: list[str] = []
    bind: list[str] = []
    limits: dict[str, int] = {}
    section = ""
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip(PARSER_WHITESPACE)
        if not line:
            continue
        header = re.fullmatch(r"\[(.+)\]", line)
        if header:
            section = header.group(1)
            if section not in (*FILESYSTEM_SECTIONS, "connect", "bind", "limits"):
                raise ValueError(f"unknown section [{section}]")
            continue
        if section in FILESYSTEM_SECTIONS:
            check_path(line)
            fs.setdefault(line, set()).add(section)
        elif section == "connect":
            connect.append(line)
        elif section == "bind":
            bind.append(line)
        elif section == "limits":
            key, separator, value = (part.strip(PARSER_WHITESPACE) for part in line.partition("="))
            if not separator or key not in LIMIT_KEYS or not DIGITS.fullmatch(value):
                raise ValueError(f"malformed limit {line!r}")
            limits[key] = merged_limit(limits.get(key), int(value))
        else:
            raise ValueError(f"{line!r} appears before any section")
    check_limits(limits)
    return Policy(fs={path: frozenset(sections) for path, sections in fs.items()},
                  connect=tuple(connect), bind=tuple(bind), limits=limits)


def merged_limit(earlier: int | None, value: int) -> int:
    """A limit named twice, merged as set_parsed_limit merges it: zero (off) wins, otherwise the largest."""
    if earlier is None:
        return value
    if earlier == 0 or value == 0:
        return 0
    return max(earlier, value)


def covered_rights(path: str, base: Policy) -> frozenset[str]:
    """The rights the base grants a path, through an entry on the path itself or on any ancestor."""
    return frozenset().union(*(rights_of(sections) for ancestor, sections in base.fs.items()
                               if ancestor == path or is_beneath(path, ancestor)))


def remainder(exercise: Policy, base: Policy) -> Policy:
    """What an exercise's policy needs beyond the base: the per-exercise file of A.9.

    A filesystem entry keeps only the sections whose rights the base does not already grant along
    its ancestors; an entry left with none is dropped. Network rules the base names are dropped, and
    the limits stay, since the base holds none.
    """
    fs: dict[str, frozenset[str]] = {}
    for path, sections in exercise.fs.items():
        covered = covered_rights(path, base)
        kept = frozenset(section for section in sections if not SECTION_RIGHTS[section] <= covered)
        if kept:
            fs[path] = kept
    return Policy(fs=fs,
                  connect=tuple(rule for rule in exercise.connect if rule not in base.connect),
                  bind=tuple(rule for rule in exercise.bind if rule not in base.bind),
                  limits=dict(exercise.limits),
                  comments={path: text for path, text in exercise.comments.items() if path in fs})


def writable_top_level(root: pathlib.Path) -> list[str]:
    """The absolute names of the directories the permissive policy grants writing on, under `root`.

    Every top-level directory that is not a symbolic link, except NEVER_WRITABLE_TOP_LEVEL, and every
    child directory of /var except /var/tmp. `root` stands for `/`, so a test can pass a tree of its own.
    """
    names: list[str] = []
    for entry in sorted(root.iterdir()):
        name = "/" + entry.name
        if entry.is_dir() and not entry.is_symlink() and name not in NEVER_WRITABLE_TOP_LEVEL:
            names.append(name)
    var = root / "var"
    if var.is_dir():
        for entry in sorted(var.iterdir()):
            if entry.is_dir() and not entry.is_symlink() and entry.name != "tmp":
                names.append("/var/" + entry.name)
    return names


def permissive_policy(root: pathlib.Path, declared_hosts: tuple[str, ...] = ()) -> Policy:
    """The policy of A.6.4's permissive layered run: every layer on, everything an exercise could need.

    [read] and [execute] on `/`; every write-class section on the directories writable_top_level names
    and on the exercise's working directory; /dev/null read and write; loopback and port 0; and, as the
    only external [connect] rules, one per declared host (decision 11). The specification's parent
    (/var/tmp) and the candidate's directory (/run) are never writable.
    """
    fs: dict[str, frozenset[str]] = {"/": frozenset({"read", "execute"}), "/dev/null": frozenset({"read", "write"})}
    for path in [*writable_top_level(root), TESTING_DIR]:
        fs[path] = frozenset(WRITE_SECTIONS)
    return Policy(fs=fs, connect=PERMISSIVE_CONNECT + network.seed_rules(declared_hosts),
                  bind=PERMISSIVE_BIND, limits={})
