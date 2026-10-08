"""The exercise's behaviour tests, as Artemis's Python template writes them: unittest test cases run by pytest."""

import unittest

from assignment.sorting_algorithms import BubbleSort

# The template's list, in order.
ORDERED = (1, 1, 2, 3, 4, 8)


class TestSortingBehavior(unittest.TestCase):
    """The reference solution sorts the template's list and leaves an ordered one as it was."""

    def test_bubble_sort(self):
        """An unordered list comes out ordered."""
        numbers = [3, 4, 2, 1, 8, 1]
        BubbleSort().perform_sort(numbers)
        self.assertEqual(list(ORDERED), numbers)

    def test_bubble_sort_of_an_ordered_list(self):
        """An ordered list stays as it is."""
        numbers = list(ORDERED)
        BubbleSort().perform_sort(numbers)
        self.assertEqual(list(ORDERED), numbers)
