"""The reference solution: a sorting strategy that orders a list of numbers in place."""

from __future__ import annotations


class BubbleSort:
    """Bubble sort, the strategy Artemis's Python template asks for on short lists."""

    def perform_sort(self, numbers: list[int]) -> None:
        """Orders the numbers ascending, in place."""
        for end in range(len(numbers) - 1, 0, -1):
            for index in range(end):
                if numbers[index] > numbers[index + 1]:
                    numbers[index], numbers[index + 1] = numbers[index + 1], numbers[index]
