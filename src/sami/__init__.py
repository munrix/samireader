"""sami — the review layer MOSS never shipped.

:mod:`mosslib` reads archives. :mod:`sami` decides what is worth an admin's
attention, and says so in a form that survives being argued with: every finding
carries the evidence it came from, the arithmetic that produced it, a confidence
level, and the benign explanation alongside the suspicious one.

The tool never emits a verdict. See ``docs/PLAN.md`` §1 and ``docs/RESEARCH.md`` §7.
"""

from sami.version import __version__

__all__ = ["__version__"]
