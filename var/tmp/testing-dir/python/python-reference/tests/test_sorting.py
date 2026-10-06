"""The exercise's tests, as an instructor would write them for the reference solution."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "assignment"))

from sorting import sorted_numbers


def test_sorts_numbers_in_ascending_order():
    assert sorted_numbers([3, 1, 2]) == [1, 2, 3]


def test_leaves_its_input_as_it_was():
    numbers = [2, 1]
    sorted_numbers(numbers)
    assert numbers == [2, 1]
