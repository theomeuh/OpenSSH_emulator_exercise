from collections import deque

import pytest

from dijsktra import Graph


def test_path_exist():

    graph = Graph(
        [
            ("a", "b", 7),
            ("a", "c", 9),
            ("a", "f", 14),
            ("b", "c", 10),
            ("b", "d", 15),
            ("c", "d", 11),
            ("c", "f", 2),
            ("d", "e", 6),
            ("e", "f", 9),
        ]
    )
    assert graph.dijkstra("a", "e") == deque(["a", "c", "d", "e"])


def test_no_path_to_dest():

    # e has no incoming link
    graph = Graph(
        [
            ("a", "b", 7),
            ("a", "c", 9),
            ("a", "f", 14),
            ("b", "c", 10),
            ("b", "d", 15),
            ("c", "d", 11),
            ("c", "f", 2),
            ("e", "f", 9),
        ]
    )
    assert graph.dijkstra("a", "e") == deque([])


def test_src_not_exist():

    graph = Graph(
        [
            ("b", "c", 10),
            ("b", "d", 15),
            ("c", "d", 11),
            ("c", "f", 2),
            ("d", "e", 6),
            ("e", "f", 9),
        ]
    )
    with pytest.raises(AssertionError):
        assert graph.dijkstra("a", "e")
