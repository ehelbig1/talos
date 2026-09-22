"""Shared primitives for the structural lints.

One home, because the alternative has already cost this repository twice:
every detector that needed to read Rust the way Rust is WRITTEN grew its own
parser, and the ones that did not grow one silently gated nothing.
"""
