"""The records the layer pruner reasons about: one observed system call, and one attributed denial.

Both are plain frozen values with no behaviour, so that a trace can be parsed once and every later
stage (attribution, generalisation, the record written beside a pruned policy) reads the same data.
"""

from __future__ import annotations

import dataclasses

# The layers a denial can be attributed to. A grant can only ever come from the first two; a fixed
# rule of the layers, a resource limit and a refusal some other mechanism made are reported, never
# granted.
LAYER_FILESYSTEM = "filesystem"
LAYER_NETWORK = "network"
LAYER_FIXED = "fixed"
LAYER_LIMIT = "limit"
LAYER_OTHER = "other"


@dataclasses.dataclass(frozen=True)
class Syscall:
    """One completed system call as strace printed it.

    `arguments` is the text between the call's parentheses, exactly as printed, decorations
    included. `result` is the return value, or None where strace printed `?` because the call never
    returned (exit_group, a successful execve seen from the old image). `errno` is the symbolic
    error name for a failed call and None otherwise.
    """

    pid: int
    name: str
    arguments: str
    result: int | None
    errno: str | None


@dataclasses.dataclass(frozen=True)
class Denial:
    """A refused call, attributed to the layer that refused it and to what granting it would need.

    `objects` are the paths Landlock checks the missing right on (the object itself, or the parent
    directory for a creation, a removal or a rename), and `sections` the configuration sections that
    would grant it, empty where no section can. `address`, `port` and `transport` describe a network
    destination or a local port and are None otherwise. `operation` names the refused system call.
    `pid` is the refusing process (its thread-group id) and `tid` the refusing thread, the id strace
    printed; `run` numbers the observed run the denial came from, which the caller sets, so that a
    name seen changing between runs can be told apart from one seen once.
    """

    pid: int
    layer: str
    operation: str
    objects: tuple[str, ...]
    sections: frozenset[str]
    address: str | None
    port: int | None
    transport: str | None
    errno: str
    run: int = 0
    tid: int = 0
