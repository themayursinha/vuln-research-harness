"""Synthetic code-map fixture. Not a research target.

def not_a_function():
    return missing()
"""

# def commented():
#     return join_public("nope")

note = "def also_not_real():\n    return missing()\n"

from path_utils import join_public


def read_public(name):
    return join_public(name)


def local_only():
    return read_public("synthetic")
