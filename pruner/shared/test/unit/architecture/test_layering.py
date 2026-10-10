"""Holds the pruners to their layers: a module imports its own layer, a lower one, or the shared package, never more.

The layers, lowest first, are domain, infrastructure, application and interface. The shared package is lower
than both pruners and imports neither; the exercise pruner and the runtime pruner never import each other.
Only the absolute form `from <package>.src.<layer>[.<module>] import ...` is allowed for a pruner module, so
that nothing hides from this test behind `import a.b`, a relative import or a dynamic import. The domain
starts no process: it imports none of the modules that do.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

PRUNER = pathlib.Path(__file__).resolve().parents[4]
LAYERS = ("domain", "infrastructure", "application", "interface")
PACKAGES = ("shared", "exercise_pruner", "runtime_pruner")
PROCESS_MODULES = {"subprocess", "pty", "multiprocessing", "ctypes"}
ALLOWED_PACKAGES = {
    "shared": {"shared"},
    "exercise_pruner": {"exercise_pruner", "shared"},
    "runtime_pruner": {"runtime_pruner", "shared"},
}


def sources() -> list[pathlib.Path]:
    """Every Python module of the three src folders."""
    return sorted(path for package in PACKAGES for path in (PRUNER / package / "src").rglob("*.py"))


def place_of(path: pathlib.Path) -> tuple[str, str]:
    """The package and the layer a module sits in, from its path."""
    relative = path.relative_to(PRUNER).parts
    return relative[0], relative[2]


def imported_places(path: pathlib.Path) -> list[tuple[str, str, str]]:
    """The package, layer and dotted name of every pruner module the file imports."""
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in PACKAGES:
                    pytest.fail(f"{path} uses `import {alias.name}`; use `from <package>.src.<layer> import <module>`")
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            pytest.fail(f"{path} uses a relative import; use `from <package>.src.<layer> import <module>`")
        parts = (node.module or "").split(".")
        if parts[0] not in PACKAGES:
            continue
        if len(parts) < 3 or parts[1] != "src" or parts[2] not in LAYERS:
            pytest.fail(f"{path} imports {node.module}, which is not <package>.src.<layer>")
        found.append((parts[0], parts[2], node.module))
    return found


def test_there_are_modules_to_check():
    assert len(sources()) > 30


@pytest.mark.parametrize("path", sources(), ids=lambda path: str(path.relative_to(PRUNER)))
def test_a_module_imports_only_what_its_layer_may(path):
    package, layer = place_of(path)
    assert layer in LAYERS, f"{path} sits in {layer}, which is not a layer"
    for imported_package, imported_layer, name in imported_places(path):
        assert imported_package in ALLOWED_PACKAGES[package], f"{path} imports {name} from another pruner"
        assert LAYERS.index(imported_layer) <= LAYERS.index(layer), f"{path} ({layer}) imports {name} from a higher layer"


def process_modules_imported(path: pathlib.Path) -> set[str]:
    """The modules of the standard library that start or control processes which the file imports."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module.split(".")[0])
    return found & PROCESS_MODULES


@pytest.mark.parametrize("path", [path for path in sources() if place_of(path)[1] == "domain"],
                         ids=lambda path: str(path.relative_to(PRUNER)))
def test_the_domain_starts_no_process(path):
    assert not process_modules_imported(path), f"{path} is in the domain and imports {process_modules_imported(path)}"
