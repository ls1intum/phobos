"""The reference solution: sort a list of numbers and report what it did."""

from __future__ import annotations


def sorted_numbers(numbers: list[int]) -> list[int]:
    """The numbers in ascending order, as a new list; the input is left as it was."""
    result = list(numbers)
    for end in range(len(result) - 1, 0, -1):
        for index in range(end):
            if result[index] > result[index + 1]:
                result[index], result[index + 1] = result[index + 1], result[index]
    return result
